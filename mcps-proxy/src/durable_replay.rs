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
//! Like the in-memory reference cache there is NO background clock: pruning of
//! expired entries is explicit ([`prune`](DurableReplayCache::prune)); a present
//! entry is a replay until pruned.
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

/// A file-backed durable replay cache.
#[derive(Debug)]
pub struct DurableReplayCache {
    path: PathBuf,
    max_clock_skew_secs: i64,
    entries: BTreeMap<Key, i64>,
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
        })
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
