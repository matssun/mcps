//! SINGLE-NODE durable file-backed [`ReplayCache`] (MCPS-028, ADR-MCPS-014).
//!
//! This is **single-node durable replay protection**, NOT distributed replay
//! protection. It survives process restarts on one host WITHOUT an external
//! service, and is the correct backend for a single-node deployment. A
//! horizontally-scaled deployment (multiple proxy processes / hosts) needs a
//! shared atomic cache (e.g. Redis) behind the same `mcps_core::ReplayCache`
//! trait — that is a documented future backend, and using this file cache across
//! several nodes would NOT protect against replay (each node sees only its own
//! file).
//!
//! Entries are keyed by the `(signer, audience, nonce)` triple and carry a
//! `retain_until` instant (`expires_at + max_clock_skew`). The whole state is
//! persisted as JSON on every insert via a temp-file + fsync + atomic rename:
//! the temp file is flushed to stable storage (`sync_all`) BEFORE the rename and
//! the containing directory is fsync'd AFTER it, so neither a concurrent reader
//! (`open` never observes a half-written file) nor a crash / power loss
//! immediately after a successful insert can lose a just-accepted nonce
//! (MCPS-083 / audit M-8). A persistence failure surfaces as [`ReplayCacheError`]
//! (→ `mcps.replay_cache_unavailable`, fail closed) and the in-memory insert is
//! rolled back so a transient failure can be retried.
//!
//! Rollback scope — be precise about what is and is NOT detected:
//!   * IN-PROCESS rollback on a failed persist IS handled (the in-memory insert
//!     is reverted; see [`check_and_insert`](DurableReplayCache::check_and_insert)).
//!   * EXTERNAL rollback of the state file (restoring it from a snapshot/backup)
//!     is NOT detected — there is no monotonic counter or external anchor to
//!     compare against. Such a rollback can reopen a replay window for the
//!     rolled-back interval. Mitigate by keeping freshness windows
//!     (`expires_at - issued_at`) short and not restoring this file from stale
//!     snapshots. (Crash / power-loss durability of a just-accepted nonce IS
//!     handled, by the fsync-before-rename + directory fsync in `persist`.)
//!
//! A corrupt or unreadable existing file fails closed at [`open`](DurableReplayCache::open).
//!
//! Eviction happens two ways: an explicit [`prune`](DurableReplayCache::prune)
//! (e.g. a periodic operator/scheduler call), AND an opportunistic,
//! bounded-cadence prune run inline from
//! [`check_and_insert`](DurableReplayCache::check_and_insert) so growth is bounded
//! even with no external scheduler (finding #140). The inline prune anchors on the
//! store's OWN injected clock (system time in production; a fixed clock in tests),
//! NOT on the in-flight request's `expires_at_unix` — a fresh request's expiry can
//! be arbitrarily far ahead of real `now` (freshness only bounds `now <=
//! expires_at + skew`), so using it as the prune anchor could evict still-live
//! entries and reopen a replay window. A hard fail-closed ceiling (`MAX_ENTRIES`) caps retained
//! entries: past it, `check_and_insert` returns
//! [`ReplayCacheError::Unavailable`] rather than growing unbounded — never a
//! silent "allow". A present, unexpired entry is still a replay until pruned.
//!
//! Concurrency: a single [`DurableReplayCache`] is NOT internally synchronized
//! (`&mut self` on insert); the proxy serializes access (single-threaded serve
//! loop / interior `RefCell`). Two PROCESSES sharing one file is unsupported —
//! last-writer-wins on the rename can drop the other's entries.

use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use mcps_core::ReplayCache;
use mcps_core::ReplayCacheError;
use mcps_core::ReplayDecision;
use mcps_core::ReplayDurabilityClass;
use serde_json::json;
use serde_json::Value;

/// The `(signer, audience, nonce)` replay key.
type Key = (String, String, String);

/// Source of the current Unix time (seconds) for the inline-prune anchor. The
/// `ReplayCache` trait carries no clock, so the store owns one at its impure edge
/// (mirrors `redis_store`/`etcd_store`). Production injects [`system_clock`];
/// tests inject a fixed clock so the prune boundary is deterministic.
type UnixClock = Box<dyn Fn() -> i64 + Send + Sync>;

/// The production [`UnixClock`]: reads the system clock, clamping a pre-epoch
/// reading (impossible on a sane host) to 0 rather than panicking.
fn system_clock() -> UnixClock {
    Box::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    })
}

/// How often (in admitted inserts) `check_and_insert` runs an opportunistic
/// prune of expired entries.
///
/// The `ReplayCache` trait carries no clock, so there is no production prune
/// scheduler the file cache can be wired into (finding #140 / ledger
/// `590b3f2977fe8ef3`). Without this, every accepted nonce is retained forever
/// and each insert rewrites the ENTIRE map to disk — O(n) bytes + two fsyncs per
/// request, O(n^2) cumulative I/O — so an authentic peer streaming distinct
/// fresh nonces drives unbounded disk and per-request latency. We instead prune
/// inline on a bounded cadence, keyed on `retain_until`, so the retained count
/// (and thus per-insert I/O) is bounded by the freshness window rather than by
/// total request volume. Pruning every insert would itself be O(n); a small
/// cadence amortises it while keeping the bound tight.
const PRUNE_EVERY_N_INSERTS: u64 = 64;

/// Fail-closed ceiling on retained entries. Even with opportunistic pruning a
/// pathological peer could, within a single freshness window, present more
/// distinct fresh nonces than memory/disk can hold. Past this ceiling (after a
/// prune attempt) the cache refuses further inserts with
/// [`ReplayCacheError::Unavailable`] (→ `mcps.replay_cache_unavailable`, fail
/// closed) rather than growing without bound — never a silent "allow". The
/// window drains the backlog as entries expire.
const MAX_ENTRIES: usize = 1_000_000;

/// A file-backed durable replay cache.
pub struct DurableReplayCache {
    path: PathBuf,
    max_clock_skew_secs: i64,
    entries: BTreeMap<Key, i64>,
    /// Count of admitted inserts since open; drives the opportunistic-prune
    /// cadence (`PRUNE_EVERY_N_INSERTS`).
    inserts_since_prune: u64,
    /// Fail-closed ceiling on retained entries (defaults to [`MAX_ENTRIES`]).
    /// Held as a field so tests can exercise the ceiling cheaply without
    /// inserting a million entries; production always uses the default.
    max_entries: usize,
    /// Clock for the inline-prune anchor (system time in production; injected in
    /// tests). The trait carries no clock, so the store owns one.
    clock: UnixClock,
}

impl std::fmt::Debug for DurableReplayCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurableReplayCache")
            .field("path", &self.path)
            .field("max_clock_skew_secs", &self.max_clock_skew_secs)
            .field("entries", &self.entries.len())
            .field("inserts_since_prune", &self.inserts_since_prune)
            .field("max_entries", &self.max_entries)
            .finish_non_exhaustive()
    }
}

impl DurableReplayCache {
    /// Open (or create) a durable cache at `path`, loading any existing entries.
    /// Returns an error only if an existing file is present but unreadable/corrupt.
    pub fn open(path: impl AsRef<Path>, max_clock_skew_secs: i64) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let entries = if path.exists() {
            load(&path)?
        } else {
            BTreeMap::new()
        };
        Ok(DurableReplayCache {
            path,
            max_clock_skew_secs,
            entries,
            inserts_since_prune: 0,
            max_entries: MAX_ENTRIES,
            clock: system_clock(),
        })
    }

    /// Test-only: override the fail-closed entry ceiling so the ceiling path can
    /// be exercised without inserting [`MAX_ENTRIES`] real (fsynced) entries.
    #[cfg(test)]
    fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    /// Test-only: inject a fixed clock so the inline-prune anchor is deterministic.
    #[cfg(test)]
    fn with_clock(mut self, clock: UnixClock) -> Self {
        self.clock = clock;
        self
    }

    /// Drop every entry whose `retain_until < now_unix` and persist. Call
    /// periodically to bound growth.
    ///
    /// The retain-until boundary is `>=` (an entry is KEPT through its
    /// `retain_until` and evicted only strictly past it), matching the in-memory
    /// reference store's canonical semantics
    /// ([`InMemoryAtomicReplayStore::prune`](crate::shared_replay::InMemoryAtomicReplayStore::prune),
    /// whose own test asserts this `>=` boundary as the intended contract). Both
    /// boundaries are safe (past `retain_until` the nonce can no longer pass the
    /// freshness window, so readmission is not exploitable); aligning them removes
    /// a one-second cross-backend inconsistency in the exact eviction instant.
    pub fn prune(&mut self, now_unix: i64) -> io::Result<()> {
        self.entries.retain(|_, &mut retain_until| retain_until >= now_unix);
        persist(&self.path, &self.entries)
    }

    /// Number of live entries (test/inspection aid).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl ReplayCache for DurableReplayCache {
    fn check_and_insert(
        &mut self,
        signer: &str,
        audience: &str,
        nonce: &str,
        expires_at_unix: i64,
    ) -> Result<ReplayDecision, ReplayCacheError> {
        let key: Key = (signer.to_string(), audience.to_string(), nonce.to_string());
        if self.entries.contains_key(&key) {
            return Ok(ReplayDecision::Replay);
        }

        // Opportunistic, bounded-cadence prune of expired entries (finding #140).
        // The `ReplayCache` trait carries no clock, so there is no production
        // prune scheduler to wire into; instead we evict inline so retained count
        // and per-insert I/O stay bounded by the freshness window rather than
        // total request volume. The anchor is the store's OWN clock (system time
        // in production) — NOT the request's `expires_at_unix`, which can be
        // arbitrarily far ahead of real `now` (freshness only bounds `now <=
        // expires_at + skew`) and would over-evict still-live entries, reopening a
        // replay window. Pruning at the real `now` evicts only entries strictly
        // past their own `retain_until` (`>=` boundary, matching `prune`).
        self.inserts_since_prune = self.inserts_since_prune.saturating_add(1);
        if self.inserts_since_prune >= PRUNE_EVERY_N_INSERTS {
            self.inserts_since_prune = 0;
            let now = (self.clock)();
            self.entries
                .retain(|_, &mut retain_until| retain_until >= now);
        }

        // Fail-closed ceiling: never grow without bound. If, even after the prune
        // above, admitting this entry would exceed the cap, refuse it as
        // Unavailable (→ `mcps.replay_cache_unavailable`) rather than allow or
        // grow unbounded. The freshness window drains the backlog over time.
        if self.entries.len() >= self.max_entries {
            return Err(ReplayCacheError::Unavailable {
                details: format!(
                    "replay cache at capacity ({} entries); refusing to admit further nonces until expired entries drain",
                    self.max_entries
                ),
            });
        }

        let retain_until = expires_at_unix.saturating_add(self.max_clock_skew_secs);
        self.entries.insert(key.clone(), retain_until);
        if let Err(e) = persist(&self.path, &self.entries) {
            // Roll back so a transient persistence failure can be retried.
            self.entries.remove(&key);
            return Err(ReplayCacheError::Unavailable {
                details: format!("persist failed: {e}"),
            });
        }
        Ok(ReplayDecision::Fresh)
    }

    /// Durable: admitted nonces are fsync-persisted (temp-file + rename + dir
    /// fsync) and re-read from disk on restart, so a restart does NOT forget them
    /// (ADR-MCPS-014/020). Single-node — horizontal strength is asserted by the
    /// proxy's `ReplayDurabilityTier`, not by this class — but durable, so it
    /// clears the strict object-level durability gate (#78).
    fn durability_class(&self) -> ReplayDurabilityClass {
        ReplayDurabilityClass::Durable
    }
}

/// Serialize the entries to `path` atomically (temp file + rename).
fn persist(path: &Path, entries: &BTreeMap<Key, i64>) -> io::Result<()> {
    let array: Vec<Value> = entries
        .iter()
        .map(|((signer, audience, nonce), retain_until)| {
            json!({
                "signer": signer,
                "audience": audience,
                "nonce": nonce,
                "retain_until": retain_until,
            })
        })
        .collect();
    let bytes = serde_json::to_vec(&Value::Array(array))
        .map_err(|e| io::Error::other(e.to_string()))?;

    // Durable temp-file + atomic rename (MCPS-083 / audit M-8). std::fs::write +
    // rename gives a concurrent reader all-or-nothing visibility but NOT crash
    // durability: without an fsync, a power loss after this function returns can
    // leave the rename or the file contents unflushed, dropping a just-accepted
    // nonce so the same request replays after restart. So: flush the temp file's
    // data + metadata to stable storage BEFORE the rename, then fsync the
    // containing directory AFTER it so the rename itself is durable.
    let tmp = path.with_extension("tmp");
    {
        let mut file = File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    // Fsync the directory entry created by the rename. A bare filename has an
    // empty parent, which denotes the current directory.
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Load entries from `path`.
fn load(path: &Path) -> io::Result<BTreeMap<Key, i64>> {
    let bytes = std::fs::read(path)?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|e| io::Error::other(e.to_string()))?;
    let array = value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "replay cache is not a JSON array"))?;

    let mut entries = BTreeMap::new();
    for entry in array {
        let signer = entry["signer"].as_str();
        let audience = entry["audience"].as_str();
        let nonce = entry["nonce"].as_str();
        let retain_until = entry["retain_until"].as_i64();
        match (signer, audience, nonce, retain_until) {
            (Some(s), Some(a), Some(n), Some(r)) => {
                entries.insert((s.to_string(), a.to_string(), n.to_string()), r);
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed replay cache entry",
                ))
            }
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::DurableReplayCache;
    use mcps_core::ReplayCache;
    use mcps_core::ReplayCacheError;
    use mcps_core::ReplayDecision;
    use mcps_core::ReplayDurabilityClass;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("mcps_replay_{}_{name}", std::process::id()))
    }

    #[test]
    fn declares_durable_class() {
        // #78 (ADR-MCPS-020): the fsync-persisted file-backed cache survives
        // restart, so it must self-declare Durable — letting the strict
        // object-level gate accept it where the volatile reference cache is
        // rejected.
        let path = tmp("durable_class");
        let _ = std::fs::remove_file(&path);
        let cache = DurableReplayCache::open(&path, 300).unwrap();
        assert_eq!(cache.durability_class(), ReplayDurabilityClass::Durable);
        assert!(!cache.is_single_process_reference());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn first_is_fresh_then_replay() {
        let path = tmp("fresh_replay");
        let _ = std::fs::remove_file(&path);
        let mut cache = DurableReplayCache::open(&path, 300).unwrap();
        assert_eq!(
            cache.check_and_insert("s", "a", "n1", 1000).unwrap(),
            ReplayDecision::Fresh
        );
        assert_eq!(
            cache.check_and_insert("s", "a", "n1", 1000).unwrap(),
            ReplayDecision::Replay
        );
        // A different nonce is fresh.
        assert_eq!(
            cache.check_and_insert("s", "a", "n2", 1000).unwrap(),
            ReplayDecision::Fresh
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn survives_reopen() {
        let path = tmp("reopen");
        let _ = std::fs::remove_file(&path);
        {
            let mut cache = DurableReplayCache::open(&path, 300).unwrap();
            assert_eq!(
                cache.check_and_insert("s", "a", "n", 1000).unwrap(),
                ReplayDecision::Fresh
            );
        }
        // Reopen: the nonce must still be seen as a replay.
        let mut reopened = DurableReplayCache::open(&path, 300).unwrap();
        assert_eq!(
            reopened.check_and_insert("s", "a", "n", 1000).unwrap(),
            ReplayDecision::Replay
        );
        let _ = std::fs::remove_file(&path);
    }

    /// MCPS-083 / audit M-8: a successful insert commits the state atomically —
    /// the main file exists and round-trips, and no `.tmp` sibling is left behind
    /// (the fsync-before-rename + directory-fsync sequence in `persist` must
    /// complete the rename, never leave a partial temp file). The crash /
    /// power-loss durability the fsync adds is not observable from a running
    /// process; this locks the atomic-commit contract the fix must preserve.
    #[test]
    fn persist_commits_atomically_leaving_no_tmp_sibling() {
        let path = tmp("atomic_commit");
        let tmp_sibling = path.with_extension("tmp");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp_sibling);

        let mut cache = DurableReplayCache::open(&path, 300).unwrap();
        cache.check_and_insert("s", "a", "n", 1000).unwrap();

        assert!(path.exists(), "committed replay file must exist after insert");
        assert!(
            !tmp_sibling.exists(),
            "no .tmp sibling may remain after a committed insert"
        );
        // Durable content: a reopen sees the nonce as a replay.
        let mut reopened = DurableReplayCache::open(&path, 300).unwrap();
        assert_eq!(
            reopened.check_and_insert("s", "a", "n", 1000).unwrap(),
            ReplayDecision::Replay
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn prune_removes_expired_and_frees_the_nonce() {
        let path = tmp("prune");
        let _ = std::fs::remove_file(&path);
        let mut cache = DurableReplayCache::open(&path, 0).unwrap();
        // retain_until = 1000 + 0 = 1000.
        cache.check_and_insert("s", "a", "n", 1000).unwrap();
        // Prune at now=2000 (> retain_until) drops it.
        cache.prune(2000).unwrap();
        assert!(cache.is_empty());
        // The nonce is fresh again.
        assert_eq!(
            cache.check_and_insert("s", "a", "n", 3000).unwrap(),
            ReplayDecision::Fresh
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn persist_failure_is_unavailable_and_rolls_back() {
        // A path inside a non-existent directory cannot be written.
        let path = tmp("nope_dir").join("inner").join("cache.json");
        let mut cache = DurableReplayCache::open(&path, 300).unwrap();
        let err = cache.check_and_insert("s", "a", "n", 1000).unwrap_err();
        assert!(matches!(err, ReplayCacheError::Unavailable { .. }));
        // Rolled back: not retained in memory.
        assert!(cache.is_empty());
    }

    // --- crash-consistency / durability ---

    #[test]
    fn corrupt_file_fails_closed_on_open() {
        // A partially-written / garbage state file must not be silently treated
        // as empty (which would reopen a replay window) — open() fails closed.
        let path = tmp("corrupt");
        std::fs::write(&path, b"{ this is not valid json").unwrap();
        assert!(
            DurableReplayCache::open(&path, 300).is_err(),
            "a corrupt cache file must fail closed, not load as empty"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn malformed_entry_fails_closed_on_open() {
        // Valid JSON, wrong shape (missing nonce) → fail closed.
        let path = tmp("malformed_entry");
        std::fs::write(&path, br#"[{"signer":"s","audience":"a"}]"#).unwrap();
        assert!(DurableReplayCache::open(&path, 300).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn leftover_tmp_file_does_not_corrupt_load() {
        // A crash mid-write leaves a `.tmp` sibling and an intact main file
        // (atomic rename never half-writes the main file). Reopen must ignore the
        // leftover tmp and load the committed state cleanly.
        let path = tmp("leftover_tmp");
        let _ = std::fs::remove_file(&path);
        {
            let mut cache = DurableReplayCache::open(&path, 300).unwrap();
            cache.check_and_insert("s", "a", "n", 1000).unwrap();
        }
        // Simulate interrupted write: a stale temp file beside the good main file.
        std::fs::write(path.with_extension("tmp"), b"garbage-interrupted-write").unwrap();
        let mut reopened = DurableReplayCache::open(&path, 300).unwrap();
        assert_eq!(
            reopened.check_and_insert("s", "a", "n", 1000).unwrap(),
            ReplayDecision::Replay,
            "committed nonce survives a leftover interrupted-write temp file"
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("tmp"));
    }

    #[test]
    fn persisted_file_is_always_valid_json_after_insert() {
        // The atomic temp+rename guarantees the on-disk file is a complete,
        // parseable document after every successful insert (never half-written).
        let path = tmp("valid_json");
        let _ = std::fs::remove_file(&path);
        let mut cache = DurableReplayCache::open(&path, 300).unwrap();
        for i in 0..25 {
            cache.check_and_insert("s", "a", &format!("n{i}"), 1000).unwrap();
            let bytes = std::fs::read(&path).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert!(value.is_array(), "on-disk state stays a valid JSON array");
        }
        // And it reopens consistently with every committed nonce intact.
        let mut reopened = DurableReplayCache::open(&path, 300).unwrap();
        assert_eq!(reopened.len(), 25);
        assert_eq!(
            reopened.check_and_insert("s", "a", "n0", 1000).unwrap(),
            ReplayDecision::Replay
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The prune retain-until boundary is `>=`, matching the in-memory reference
    /// store's canonical contract (`shared_replay`'s
    /// `skew_folded_into_retain_until_matches_in_memory_semantics`): pruning AT
    /// `retain_until` KEEPS the entry; pruning strictly past it evicts. This locks
    /// the two backends to the SAME eviction instant (no one-second drift).
    #[test]
    fn prune_boundary_keeps_entry_at_retain_until_matches_in_memory() {
        let path = tmp("prune_boundary");
        let _ = std::fs::remove_file(&path);
        // skew = 30, expires_at = 1000 → retain_until = 1030.
        let mut cache = DurableReplayCache::open(&path, 30).unwrap();
        cache.check_and_insert("s", "a", "n", 1000).unwrap();
        let retain_until = 1030;
        // Prune AT retain_until keeps the entry (retain_until >= now).
        cache.prune(retain_until).unwrap();
        assert_eq!(
            cache.check_and_insert("s", "a", "n", 1000).unwrap(),
            ReplayDecision::Replay,
            "entry is live THROUGH its retain-until (>= boundary, in-memory parity)"
        );
        // Prune strictly past retain_until evicts → fresh again.
        cache.prune(retain_until + 1).unwrap();
        assert!(cache.is_empty());
        assert_eq!(
            cache.check_and_insert("s", "a", "n", 2000).unwrap(),
            ReplayDecision::Fresh
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Finding #140 regression: with NO explicit `prune()` call, streaming a long
    /// run of distinct fresh nonces whose `expires_at_unix` advances forward must
    /// NOT retain every nonce forever — the inline opportunistic prune
    /// (`check_and_insert`) evicts entries that have fallen past their
    /// retain-until. Without the inline prune the map grows monotonically and this
    /// assertion (bounded retained count) fails.
    #[test]
    fn streaming_fresh_nonces_prunes_inline_without_explicit_prune() {
        let path = tmp("inline_prune");
        let _ = std::fs::remove_file(&path);
        // Fixed clock at now = 2000; skew = 0 so retain_until == expires_at_unix.
        // Every streamed nonce expires before `now`, so each cadence-triggered
        // prune (anchored on the store's clock, NOT the request) evicts the
        // accumulated batch. We never call prune() explicitly.
        let mut cache = DurableReplayCache::open(&path, 0)
            .unwrap()
            .with_clock(Box::new(|| 2_000));

        let runs = (super::PRUNE_EVERY_N_INSERTS * 4) as i64;
        for i in 0..runs {
            // expires_at stays below the fixed `now` (2000), so by the time the
            // cadence prune runs each earlier entry is strictly past its
            // retain-until and is evicted.
            let expires_at = 1_000 + i % 500;
            assert_eq!(
                cache
                    .check_and_insert("s", "a", &format!("n{i}"), expires_at)
                    .unwrap(),
                ReplayDecision::Fresh
            );
        }

        // Retained count is bounded by the freshness window (here ~one cadence
        // batch), NOT by total inserts. Without the inline prune this would be
        // `runs` entries; with it the count stays far below.
        assert!(
            cache.len() < super::PRUNE_EVERY_N_INSERTS as usize * 2,
            "inline prune must bound retained entries (got {}, streamed {})",
            cache.len(),
            runs
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The inline prune NEVER evicts a still-live entry: it anchors on the store's
    /// real clock, so a nonce still within its freshness window (`retain_until >=
    /// now`) survives the cadence-triggered prune.
    #[test]
    fn inline_prune_never_evicts_a_live_entry() {
        let path = tmp("inline_prune_safe");
        let _ = std::fs::remove_file(&path);
        // Fixed clock now = 5000; long-lived nonce retain_until = 100_030 >> now.
        let mut cache = DurableReplayCache::open(&path, 30)
            .unwrap()
            .with_clock(Box::new(|| 5_000));

        cache.check_and_insert("s", "a", "long", 100_000).unwrap();

        // Stream enough already-expired (relative to now=5000) nonces to trigger
        // the cadence prune; they are evicted, the long-lived entry is not.
        for i in 0..(super::PRUNE_EVERY_N_INSERTS as i64 + 5) {
            cache
                .check_and_insert("s", "a", &format!("n{i}"), 1_000 + i)
                .unwrap();
        }

        assert_eq!(
            cache.check_and_insert("s", "a", "long", 100_000).unwrap(),
            ReplayDecision::Replay,
            "a still-live entry must survive the inline opportunistic prune"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Regression for the over-eviction bug Copilot flagged on #167: the inline
    /// prune must anchor on the store's REAL clock, NOT the in-flight request's
    /// `expires_at_unix`. A fresh request's expiry can be far ahead of real `now`
    /// (freshness only bounds `now <= expires_at + skew`), so anchoring on it would
    /// evict still-live entries and reopen a replay window. Here a live nonce
    /// (retain_until just above `now`) must SURVIVE a cadence prune triggered by a
    /// flood of requests whose `expires_at` is far in the future. Under the old
    /// `safe_now_floor(expires_at)` anchor the live entry was wrongly evicted and
    /// this would return `Fresh`.
    #[test]
    fn inline_prune_anchors_on_real_clock_not_request_expiry() {
        let path = tmp("inline_prune_clock");
        let _ = std::fs::remove_file(&path);
        // Fixed clock now = 1000; live nonce retain_until = 2000 (> now).
        let mut cache = DurableReplayCache::open(&path, 0)
            .unwrap()
            .with_clock(Box::new(|| 1_000));
        cache.check_and_insert("s", "a", "live", 2_000).unwrap();

        // Flood with far-future-expiry requests to trigger the cadence prune. The
        // buggy anchor would be ~1_000_000 and evict the retain_until=2000 entry.
        for i in 0..(super::PRUNE_EVERY_N_INSERTS as i64 + 5) {
            cache
                .check_and_insert("s", "a", &format!("future{i}"), 1_000_000 + i)
                .unwrap();
        }

        assert_eq!(
            cache.check_and_insert("s", "a", "live", 2_000).unwrap(),
            ReplayDecision::Replay,
            "a live entry (retain_until > real now) must NOT be evicted by a prune \
             triggered by far-future-expiry requests — anchor must be the real clock"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Finding #140 fail-closed ceiling: if even after the inline prune the cache
    /// is at capacity, admitting another distinct fresh nonce must FAIL CLOSED
    /// (`Unavailable`), never grow unbounded and never silently allow. Here every
    /// entry is long-lived (high expires_at, skew 0) so the inline prune cannot
    /// reclaim space, forcing the ceiling.
    #[test]
    fn ceiling_fails_closed_when_full_of_live_entries() {
        let path = tmp("ceiling");
        let _ = std::fs::remove_file(&path);
        let cap = 8;
        let mut cache = DurableReplayCache::open(&path, 0).unwrap().with_max_entries(cap);
        // Fill to capacity with non-expiring (far-future) nonces.
        for i in 0..cap as i64 {
            assert_eq!(
                cache
                    .check_and_insert("s", "a", &format!("n{i}"), 1_000_000)
                    .unwrap(),
                ReplayDecision::Fresh
            );
        }
        // One more distinct fresh nonce must be refused as Unavailable, not admitted.
        let err = cache
            .check_and_insert("s", "a", "overflow", 1_000_000)
            .unwrap_err();
        assert!(
            matches!(err, ReplayCacheError::Unavailable { .. }),
            "at capacity the cache must fail closed, never grow unbounded or allow"
        );
        // It was NOT admitted (no silent growth): still at the cap.
        assert_eq!(cache.len(), cap);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn expired_entries_evicted_safely_then_nonce_is_fresh() {
        let path = tmp("evict_safe");
        let _ = std::fs::remove_file(&path);
        let mut cache = DurableReplayCache::open(&path, 0).unwrap();
        cache.check_and_insert("s", "a", "n", 1000).unwrap();
        cache.prune(2000).unwrap();
        // Eviction persisted: a reopen does not resurrect the pruned nonce.
        let mut reopened = DurableReplayCache::open(&path, 0).unwrap();
        assert!(reopened.is_empty());
        assert_eq!(
            reopened.check_and_insert("s", "a", "n", 3000).unwrap(),
            ReplayDecision::Fresh
        );
        let _ = std::fs::remove_file(&path);
    }
}
