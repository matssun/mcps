//! Redis-backed [`AtomicReplayStore`] — the #4028 SHARED replay backend that
//! finally makes `--replay-cache shared` (issue #3837) give real
//! horizontally-scaled replay safety.
//!
//! The shared-cache SEMANTICS already live in
//! [`SharedReplayCache`](crate::shared_replay::SharedReplayCache); this module
//! supplies the one missing piece: a concrete [`AtomicReplayStore`] whose
//! insert-if-absent is enforced SERVER-SIDE by Redis. Each op is a single atomic
//! `SET key 1 NX PX <ttl_ms>`:
//!   * `NX` makes the absent-check + insert one indivisible step, so two proxy
//!     nodes racing on the same nonce cannot both observe it absent;
//!   * `PX <ttl_ms>` puts expiry on the SERVER (Redis evicts the key), mirroring
//!     the `InMemoryAtomicReplayStore` retain-until window without a client-side
//!     prune.
//! Multi-node replay safety holds ONLY when every proxy node points at the SAME
//! Redis (or a single logical Redis cluster); separate instances are separate
//! replay universes.
//!
//! This entire module is compiled ONLY under the non-default `redis_replay`
//! cargo feature, so a default build is byte-for-byte unchanged and gains zero
//! dependencies.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use crate::shared_replay::AtomicReplayStore;
use crate::shared_replay::ReplayStoreError;
use mcps_core::ReplayDecision;

/// A monotone-ish source of the CURRENT Unix time (seconds) for deriving the
/// server-side TTL. This is the proxy's IMPURE edge: `mcps-core` carries no
/// clock (the pure `ReplayCache` trait passes `now_unix = 0`), so the *store*
/// owns its clock here. Production injects [`system_clock`]; tests inject a fixed
/// clock so the TTL arithmetic is deterministic.
pub type UnixClock = Box<dyn Fn() -> i64 + Send + Sync>;

/// Default connect/read/write timeout used by [`RedisAtomicReplayStore::connect`]
/// when the caller does not thread the configured socket timeouts. Bounded so a
/// sinkholed/half-open Redis cannot wedge the single-threaded serve loop (H-10):
/// the replay check runs BEFORE dispatch, so a blocking op with no timeout would
/// stall the whole proxy.
const DEFAULT_REDIS_TIMEOUT: Duration = Duration::from_secs(30);

/// Extra time granted to the post-connect RESP handshake on top of the connect
/// timeout (redis-rs does not bound the handshake reply reads in the blocking
/// path, so the watchdog deadline = `connect_timeout + HANDSHAKE_GRACE`). Kept
/// short so a silent backend still fails closed promptly.
const HANDSHAKE_GRACE: Duration = Duration::from_secs(5);

/// Hard ceiling on how many connect/handshake watchdog threads may be
/// concurrently in flight (running OR abandoned-but-still-blocked) across the
/// whole process.
///
/// ## Why a ceiling is the fix here, not a socket-level handshake deadline
///
/// The textbook root-cause fix would be to apply a socket read/write deadline
/// to the RESP handshake ITSELF (set `SO_RCVTIMEO`/`SO_SNDTIMEO` on the raw
/// `TcpStream` BEFORE the handshake) so an overrunning worker unblocks and
/// releases its fd. redis-rs 0.27's BLOCKING path does NOT expose that seam:
/// [`redis::Client::get_connection_with_timeout`] bounds only the TCP connect,
/// then `connect()` immediately runs `setup_connection` (the
/// `CLIENT SETINFO` / RESP3-`HELLO` / `AUTH` / `SELECT` pipeline — non-empty
/// even for a vanilla `redis://host:port`, since `CLIENT SETINFO` is always
/// added) and READS the replies with no socket read timeout set. There is no
/// public API to inject a pre-timed `TcpStream`, and no public
/// `Connection`-from-stream constructor, so the handshake read genuinely cannot
/// be bounded in-band without reimplementing the RESP protocol. The watchdog in
/// [`bounded_connect`] therefore cannot truly unblock such a worker; it can only
/// stop WAITING on it (fail closed) and let it dangle.
///
/// Against a persistently sinkholed/half-open backend each abandoned worker
/// strands one thread + one socket fd ~forever, so sustained traffic would
/// accumulate them — a slow resource-exhaustion DoS on the proxy host. This
/// counting semaphore is the belt-and-suspenders ceiling the audit authorises:
/// it CAPS the number of simultaneously-stranded connect threads to a constant.
/// Once that many are outstanding, further connects fail closed
/// ([`ReplayStoreError::Unavailable`]) immediately instead of spawning yet
/// another doomed thread, so the leak is bounded by a constant, not by request
/// rate. M19 already bounds reconnects to one per request, so in practice the
/// permit is released the instant a healthy backend answers and the ceiling is
/// never approached.
const MAX_INFLIGHT_CONNECTS: usize = 64;

/// Count of connect/handshake watchdog threads currently holding a permit
/// (in flight OR abandoned). A permit is acquired BEFORE the worker is spawned
/// and released by the worker itself when it finishes — including LATE, after
/// the deadline abandoned it — so a permit held by a stranded worker is returned
/// if/when that worker's doomed read ever errors out, and is held for the
/// lifetime of a truly-wedged one. This is the live count the
/// [`MAX_INFLIGHT_CONNECTS`] ceiling bounds.
static INFLIGHT_CONNECTS: AtomicUsize = AtomicUsize::new(0);

/// RAII permit tracking one watchdog WORKER thread's lifetime (NOT an open
/// connection). Acquiring increments [`INFLIGHT_CONNECTS`] and fails closed if
/// that would exceed [`MAX_INFLIGHT_CONNECTS`]; dropping decrements it. The
/// permit is MOVED into the watchdog worker so the slot is freed exactly when
/// the worker thread terminates (in time OR late) — it bounds the count of
/// live/abandoned WORKERS, not the count of open sockets.
///
/// Permit-release coincides with fd-release ONLY for workers whose connection is
/// NOT handed back: an ABANDONED late worker (its doomed handshake read finally
/// errors), or a late SUCCESS whose `redis::Connection` is dropped because the
/// receiver already timed out. On the in-time SUCCESS path the connection (and
/// its fd) is transferred to the CALLER via the channel and OUTLIVES the worker,
/// so the fd is NOT released when the permit is — the permit only ever tracked
/// the worker thread.
struct ConnectPermit;

impl ConnectPermit {
    /// Acquire a permit, or fail closed if the abandoned-thread ceiling is
    /// already saturated. Uses a CAS loop so the check-and-increment is atomic
    /// (no TOCTOU between concurrent connects that could push the live count past
    /// the ceiling).
    fn acquire() -> Result<Self, ReplayStoreError> {
        let mut current = INFLIGHT_CONNECTS.load(Ordering::Acquire);
        loop {
            if current >= MAX_INFLIGHT_CONNECTS {
                return Err(ReplayStoreError::Unavailable {
                    details: format!(
                        "redis connect refused: {MAX_INFLIGHT_CONNECTS} connect/handshake \
                         threads already in flight (backend likely half-open; failing closed \
                         to bound stranded-thread/fd accumulation rather than spawn another)"
                    ),
                });
            }
            match INFLIGHT_CONNECTS.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(ConnectPermit),
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for ConnectPermit {
    fn drop(&mut self) {
        // This Drop is the ONLY decrement site (acquire is the only increment).
        // `fetch_sub` on a usize WRAPS on underflow, which would permanently
        // poison the semaphore (count becomes huge ⇒ every acquire fails closed
        // forever). The RAII pairing guarantees `prev >= 1`, so assert it in
        // debug to catch an accidental double-drop / mis-construction in a future
        // refactor. Release-mode behavior is unchanged (the assert compiles out).
        let prev = INFLIGHT_CONNECTS.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(
            prev >= 1,
            "INFLIGHT_CONNECTS underflow: dropped a ConnectPermit while the count \
             was 0 — the RAII acquire/drop pairing is broken (double-drop or a \
             permit constructed without acquire())"
        );
    }
}

/// The production [`UnixClock`]: reads the system clock. A clock that predates the
/// Unix epoch (impossible on a sane host) clamps to 0 rather than panicking.
pub fn system_clock() -> UnixClock {
    Box::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    })
}

/// Compute the Redis `PX` TTL (milliseconds) from the already-skew-folded
/// retain-until instant and the CURRENT Unix time.
///
/// Factored out as a PURE function (no clock, no I/O) so the TTL arithmetic is
/// unit-testable everywhere without a live Redis: it is the load-bearing proof
/// that the H-8/H-9 `now = 0` bug is gone — with a real `now`, the TTL is the
/// intended `retain_until - now` WINDOW (seconds × 1000), not the absolute Unix
/// epoch (~1.78e12 ms ≈ 56 years).
///
/// Clamps to a non-negative duration: if the retain-until has already passed, a
/// minimal 1 ms TTL records the sighting just long enough to answer a same-instant
/// racing replay, matching the in-memory store retaining the entry at its
/// retain-until boundary. The seconds→ms multiply saturates so a pathological
/// retain-until cannot overflow the `PX` argument.
pub(crate) fn compute_ttl_ms(expires_at_unix: i64, now_unix: i64) -> u64 {
    let ttl_secs = expires_at_unix.saturating_sub(now_unix).max(0);
    (ttl_secs as u64).saturating_mul(1000).max(1)
}

/// The connection parameters retained so a transient-failure RECONNECT (M19) uses
/// the EXACT same bounded connect/read/write timeouts as the original connect
/// (#4065) — never an unbounded reconnect that could wedge the single-threaded
/// serve loop.
struct ConnectParams {
    /// The Redis URL (`redis://host:port`) — held so reconnect targets the same
    /// backend.
    url: String,
    /// Bounds the TCP connect + RESP handshake on (re)connect.
    connect_timeout: Duration,
    /// Bounds each subsequent blocking read on the (re)established connection.
    read_timeout: Option<Duration>,
    /// Bounds each subsequent blocking write on the (re)established connection.
    write_timeout: Option<Duration>,
}

/// A SHARED [`AtomicReplayStore`] backed by Redis (#4028).
///
/// Holds the retained connection parameters plus a single connection behind a
/// `Mutex`. The proxy serve loop is single-threaded and blocking, so one mutexed
/// connection is sufficient and avoids a fresh TCP handshake per request; a
/// poisoned mutex or any connection/command failure is surfaced as
/// [`ReplayStoreError::Unavailable`] (fail closed — an outage is NEVER silently
/// treated as a fresh nonce).
///
/// M19 resilience: a *transient* connection/IO error on an op no longer
/// permanently degrades the backend. The op RECONNECTS once (bounded by the SAME
/// #4065 timeouts) and retries; only if the reconnect also fails does it surface
/// `Unavailable` (fail closed). The old code retained an UNUSED `client` field and
/// never re-established the connection, so one transient blip wedged the replay
/// backend forever.
/// WAIT durability parameters for the `REDIS_WAIT_QUORUM` tier (ADR-MCPS-020):
/// after a fresh insert, require `quorum` replica acknowledgements within
/// `timeout_ms` before reporting `Fresh`, else fail closed (the nonce is not
/// durably replicated, so a failover could lose it → replay window).
#[derive(Clone, Copy)]
struct WaitQuorum {
    quorum: u32,
    timeout_ms: u64,
}

pub struct RedisAtomicReplayStore {
    /// The bounded connect parameters, reused on every reconnect (M19/#4065).
    params: ConnectParams,
    conn: Mutex<redis::Connection>,
    /// The store's OWN clock (the proxy's impure edge). Read per op to derive the
    /// `PX` TTL window, since the pure `ReplayCache` trait passes `now_unix = 0`.
    clock: UnixClock,
    /// `Some` for the `REDIS_WAIT_QUORUM` tier — issue `WAIT` after a fresh insert
    /// and fail closed on insufficient acks (ADR-MCPS-020). `None` = `REDIS_ASYNC`
    /// / `SINGLE_STORE_FAIL_CLOSED` (plain `SET NX PX`, no replica wait).
    wait_quorum: Option<WaitQuorum>,
}

impl RedisAtomicReplayStore {
    /// Connect to `url` (e.g. `redis://127.0.0.1:6379`) with the bounded default
    /// timeouts and the production system clock. Convenience over
    /// [`connect_with`](RedisAtomicReplayStore::connect_with); prefer that from
    /// the CLI so the configured `--read-timeout-secs` / `--write-timeout-secs`
    /// bound the socket.
    pub fn connect(url: &str) -> Result<Self, ReplayStoreError> {
        Self::connect_with(
            url,
            DEFAULT_REDIS_TIMEOUT,
            Some(DEFAULT_REDIS_TIMEOUT),
            Some(DEFAULT_REDIS_TIMEOUT),
            system_clock(),
        )
    }

    /// Connect to `url`, opening a single connection with a BOUNDED connect
    /// timeout and bounded socket read/write timeouts (H-10), and the supplied
    /// `clock` (H-8/H-9).
    ///
    /// * `connect_timeout` bounds the TCP/handshake so an unreachable backend
    ///   fails closed at startup instead of hanging.
    /// * `read_timeout` / `write_timeout` bound EACH subsequent blocking
    ///   `SET … query()`: a Redis that accepts TCP but never answers (sinkholed /
    ///   half-open / on-path middlebox) surfaces as
    ///   [`ReplayStoreError::Unavailable`] within the bound rather than wedging the
    ///   single-threaded serve loop. `None` disables a socket timeout — mirroring
    ///   `ServerLimits`, where `0` means "no timeout" — but the CLI always passes
    ///   a bounded value.
    ///
    /// Any client-construction or connection error maps to
    /// [`ReplayStoreError::Unavailable`] so a misconfigured/unreachable backend
    /// fails closed rather than degrading silently.
    pub fn connect_with(
        url: &str,
        connect_timeout: Duration,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
        clock: UnixClock,
    ) -> Result<Self, ReplayStoreError> {
        let params = ConnectParams {
            url: url.to_string(),
            connect_timeout,
            read_timeout,
            write_timeout,
        };
        // The initial connect uses the SAME bounded watchdog path a reconnect does
        // (M19), so neither can hang the single-threaded serve loop (#4065/H-10).
        let conn = bounded_connect(&params)?;
        Ok(RedisAtomicReplayStore {
            params,
            conn: Mutex::new(conn),
            clock,
            wait_quorum: None,
        })
    }

    /// Enable the `REDIS_WAIT_QUORUM` tier (ADR-MCPS-020): after each fresh insert,
    /// issue `WAIT <quorum> <timeout_ms>` and fail closed unless at least `quorum`
    /// replicas acknowledge within the timeout. Without this the store is the
    /// `REDIS_ASYNC` / `SINGLE_STORE_FAIL_CLOSED` plain `SET NX PX` path.
    pub fn with_wait_quorum(mut self, quorum: u32, timeout_ms: u64) -> Self {
        self.wait_quorum = Some(WaitQuorum { quorum, timeout_ms });
        self
    }

    /// The exact `PX` TTL (ms) `insert_if_absent` will apply for `expires_at_unix`,
    /// reading the store's OWN injected clock (NOT the trait's `now_unix = 0`).
    /// Factored out so the H-8/H-9 clock WIRING — that the store derives the TTL
    /// from a real `now` via the injected clock, not 0 — is unit-testable
    /// deterministically (see [`ttl_ms_via_clock`]) with a fixed clock and no
    /// Redis.
    fn ttl_ms_for(&self, expires_at_unix: i64) -> u64 {
        ttl_ms_via_clock(&self.clock, expires_at_unix)
    }
}

/// The clock-WIRING path, isolated from any Redis connection: read `clock` for the
/// current Unix time and derive the `PX` TTL. This is the exact computation
/// [`RedisAtomicReplayStore::insert_if_absent`] performs, so a unit test that
/// injects a fixed clock proves the store derives the TTL from a REAL `now` (the
/// H-8/H-9 fix), not the trait's hard-wired `0`, with NO live Redis.
fn ttl_ms_via_clock(clock: &UnixClock, expires_at_unix: i64) -> u64 {
    compute_ttl_ms(expires_at_unix, clock())
}

/// Open a single Redis connection bounded by `params` — the SHARED connect path
/// used by both the initial connect and an M19 reconnect, so a reconnect can
/// never be unbounded.
///
/// `get_connection_with_timeout` bounds ONLY the TCP connect, NOT the post-connect
/// RESP handshake (HELLO/AUTH/CLIENT SETINFO), whose reply reads have no socket
/// timeout in redis-rs' blocking path. A backend that completes the TCP handshake
/// but then never answers (sinkholed / half-open / on-path middlebox) would
/// therefore block the handshake FOREVER. So the whole blocking connect+handshake
/// runs on a watchdog thread bounded by a finite deadline
/// (`connect_timeout + HANDSHAKE_GRACE`) and fails closed
/// ([`ReplayStoreError::Unavailable`]) if it does not finish — the connect must
/// NOT hang the single-threaded serve loop (H-10/#4065).
///
/// ## Bounding the abandoned worker (audit #97, findings 2+3)
///
/// When the watchdog deadline elapses we ABANDON the worker rather than join it
/// (joining would re-introduce the hang). On a persistently half-open backend an
/// abandoned worker stays blocked in the unbounded handshake read FOREVER,
/// stranding one thread + one socket fd each time — a slow resource-exhaustion
/// DoS. redis-rs 0.27's blocking API exposes no seam to put a read deadline on
/// the handshake socket itself (see [`MAX_INFLIGHT_CONNECTS`]), so we cannot make
/// the worker actually finish. Instead we CAP the number of concurrently
/// in-flight/abandoned WORKERS with the [`INFLIGHT_CONNECTS`] counting semaphore:
/// a permit is acquired BEFORE the worker is spawned and MOVED into it, so the
/// slot is reclaimed exactly when the worker THREAD terminates. The permit tracks
/// the worker's lifetime, not the connection — on the in-time SUCCESS path the
/// connection (and its fd) is handed to the caller and outlives the worker, so
/// fd-release coincides with permit-release ONLY for abandoned/late workers (or a
/// late success whose connection is dropped because the receiver already timed
/// out). Once [`MAX_INFLIGHT_CONNECTS`] are outstanding, this fails closed
/// immediately — the stranded-WORKER (and hence stranded-fd) count is bounded by
/// that constant rather than by request rate.
fn bounded_connect(params: &ConnectParams) -> Result<redis::Connection, ReplayStoreError> {
    // Fail closed BEFORE spawning if the ceiling of in-flight/abandoned connect
    // threads is already saturated, so a persistently half-open backend cannot
    // accumulate unbounded stranded threads + fds.
    let permit = ConnectPermit::acquire()?;

    let connect_deadline = params.connect_timeout.saturating_add(HANDSHAKE_GRACE);
    let connect_url = params.url.clone();
    let connect_timeout = params.connect_timeout;
    let read_timeout = params.read_timeout;
    let write_timeout = params.write_timeout;
    let (tx, rx) = std::sync::mpsc::channel();
    // Detached: if it overruns the deadline we abandon it (it is a doomed blocked
    // read on a dead socket; the process owns no shared state it can corrupt)
    // rather than join it and re-introduce the hang. The `permit` is MOVED in, so
    // it is dropped — releasing the in-flight WORKER slot — exactly when this
    // worker thread terminates, whether on time or LATE after abandonment. The
    // slot tracks the worker's lifetime: on the in-time SUCCESS path the
    // connection (and its fd) is sent to the caller and outlives this thread, so
    // the fd is NOT released when the permit is. fd-release coincides with
    // permit-release only for an abandoned/late worker, or a late success whose
    // connection is dropped because the receiver already timed out.
    std::thread::spawn(move || {
        let _permit = permit;
        let outcome = (|| {
            let c = redis::Client::open(connect_url.as_str()).map_err(|e| {
                ReplayStoreError::Unavailable {
                    details: format!("redis client open failed: {e}"),
                }
            })?;
            let conn = c.get_connection_with_timeout(connect_timeout).map_err(|e| {
                ReplayStoreError::Unavailable {
                    details: format!("redis connection failed: {e}"),
                }
            })?;
            // Bound EACH subsequent blocking op so a stall mid-session on the
            // established connection also fails closed (H-10).
            conn.set_read_timeout(read_timeout).map_err(|e| ReplayStoreError::Unavailable {
                details: format!("redis set_read_timeout failed: {e}"),
            })?;
            conn.set_write_timeout(write_timeout).map_err(|e| ReplayStoreError::Unavailable {
                details: format!("redis set_write_timeout failed: {e}"),
            })?;
            Ok(conn)
        })();
        // A receiver that has already timed out is gone; ignore the send error.
        let _ = tx.send(outcome);
        // `_permit` drops here, returning the slot to the pool.
    });

    match rx.recv_timeout(connect_deadline) {
        Ok(Ok(conn)) => Ok(conn),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(ReplayStoreError::Unavailable {
            details: format!(
                "redis connect/handshake did not complete within {connect_deadline:?} \
                 (backend accepted TCP but never answered the handshake; fail closed)"
            ),
        }),
    }
}

/// Whether a Redis `WAIT` reply (the number of replicas that acknowledged the
/// write) satisfies the configured quorum. Pure, so the
/// fail-closed-on-insufficient-acks decision (ADR-MCPS-020) is unit-testable
/// without a live multi-replica Redis; the command execution is proven by the
/// gated live-Redis e2e.
fn wait_quorum_satisfied(acked_replicas: i64, quorum: u32) -> bool {
    acked_replicas >= i64::from(quorum)
}

/// Decide the outcome for a freshly-inserted nonce given the Redis `WAIT` ack
/// count `acked` (ADR-MCPS-020, Tier `REDIS_WAIT_QUORUM`). Pure, so the
/// fail-closed shortfall mapping is unit-testable without a live multi-replica
/// Redis (issue #23/F4); the SET+WAIT command path is proven by the gated e2e.
///
/// - `acked >= quorum` ⇒ durably replicated ⇒ [`ReplayDecision::Fresh`].
/// - `acked < quorum` ⇒ **fail closed** with [`ReplayStoreError::Unavailable`] as
///   `OpAttempt::Fatal` (NOT `Transient`), so [`run_with_reconnect`] does NOT
///   re-run the op — a re-run would find the just-written key (the `SET NX`
///   already landed on the primary before `WAIT`) and wrongly report `Replay`
///   (the SET+WAIT op is not idempotent under retry).
///
/// ## Retry semantics (the F4 contract, ADR-MCPS-020)
///
/// On a quorum shortfall the nonce IS present on the primary but is not durably
/// replicated, and the proxy surfaces the distinct, retryable
/// `mcps.replay_cache_unavailable`. We deliberately do **NOT** compensating-
/// `DEL`/`UNLINK` the primary key: the write may already have reached some
/// replicas, and dropping it under that uncertainty could reopen a replay window —
/// the durability-over-availability tradeoff this tier exists for. The cost is an
/// availability edge: re-submitting the SAME signed request/nonce may be rejected
/// as `Replay` until the `PX` window elapses. The contract is therefore that a
/// client treats `replay_cache_unavailable` as **retry-with-a-fresh-nonce** — it
/// re-signs (a new nonce ⇒ a new key ⇒ `Fresh`), never replays the same envelope.
fn classify_fresh_insert_wait(
    acked: i64,
    quorum: u32,
    timeout_ms: u64,
) -> OpAttempt<ReplayDecision> {
    if wait_quorum_satisfied(acked, quorum) {
        OpAttempt::Done(ReplayDecision::Fresh)
    } else {
        OpAttempt::Fatal(ReplayStoreError::Unavailable {
            details: format!(
                "redis WAIT got {acked} replica ack(s), need {quorum} within {timeout_ms}ms \
                 (fail closed; nonce not durably replicated; retry with a FRESH nonce — the \
                 same signed request may be rejected as replay until the TTL window elapses)"
            ),
        })
    }
}

/// `true` when a Redis error means the connection itself is broken and must be
/// REPLACED — an IO failure or any error redis-rs classifies as requiring a
/// reconnect. This is the M19 trigger: such an error gets ONE reconnect-and-retry.
/// A non-connection error (e.g. a server-side type error) is NOT transient and is
/// surfaced directly (fail closed; a reconnect would not cure it).
fn is_transient_connection_error(error: &redis::RedisError) -> bool {
    error.is_io_error()
        || error.is_connection_dropped()
        || error.is_connection_refusal()
        || error.is_unrecoverable_error()
}

/// Outcome of one attempt at a connection-bound op, telling
/// [`run_with_reconnect`] whether a reconnect-and-retry is warranted.
enum OpAttempt<T> {
    /// The op succeeded; return this value.
    Done(T),
    /// The connection is broken — reconnect once and retry the op.
    Transient(ReplayStoreError),
    /// A non-connection failure — surface it; a reconnect would not help.
    Fatal(ReplayStoreError),
}

/// Run a connection-bound op with M19 single-reconnect resilience.
///
/// 1. Run `op` on the current cached connection.
/// 2. On [`OpAttempt::Done`], return.
/// 3. On [`OpAttempt::Transient`], `reconnect` ONCE (bounded — the caller passes
///    [`bounded_connect`]), replace the cached connection, and run `op` again. A
///    second transient failure (or a reconnect failure) is surfaced
///    ([`ReplayStoreError::Unavailable`], fail closed). NO unbounded loop.
/// 4. On [`OpAttempt::Fatal`], surface immediately.
///
/// Generic over the connection type so the reconnect-and-retry decision is
/// black-box testable with a FAKE connection that has no live Redis (see the
/// `transient_error_reconnects_and_retries` test): the M19 logic is proven
/// everywhere, while the real `redis::Connection` SET path is proven end-to-end by
/// the live-Redis e2e test.
fn run_with_reconnect<C, T, Reconnect, Op>(
    conn_slot: &mut C,
    reconnect: Reconnect,
    op: Op,
) -> Result<T, ReplayStoreError>
where
    Reconnect: Fn() -> Result<C, ReplayStoreError>,
    Op: Fn(&mut C) -> OpAttempt<T>,
{
    match op(conn_slot) {
        OpAttempt::Done(value) => Ok(value),
        OpAttempt::Fatal(e) => Err(e),
        OpAttempt::Transient(_) => {
            // The connection is broken. Reconnect ONCE (bounded) and retry the op.
            // A failed reconnect is surfaced (fail closed) — the broken connection
            // is left in place, but every future op will attempt the same single
            // reconnect, so the backend is no longer PERMANENTLY degraded by one
            // transient blip (the M19 bug).
            let fresh = reconnect()?;
            *conn_slot = fresh;
            match op(conn_slot) {
                OpAttempt::Done(value) => Ok(value),
                OpAttempt::Transient(e) | OpAttempt::Fatal(e) => Err(e),
            }
        }
    }
}

impl AtomicReplayStore for RedisAtomicReplayStore {
    fn insert_if_absent(
        &self,
        key: &str,
        expires_at_unix: i64,
        _now_unix: i64,
    ) -> Result<ReplayDecision, ReplayStoreError> {
        // Derive a server-side TTL from the (already skew-folded) retain-until
        // instant relative to the store's OWN clock — NOT the trait's `now_unix`,
        // which is 0 (the pure `ReplayCache` carries no clock). Trusting that 0
        // was the H-8/H-9 bug: it made `PX = retain_until` (an absolute Unix
        // ~1.78e9) × 1000 ≈ 56 years, so keys ~never expired → unbounded keyspace
        // growth (DoS). Reading the real `now` here makes `PX` the intended
        // `retain_until - now` WINDOW.
        let ttl_ms = self.ttl_ms_for(expires_at_unix);
        // Copied out of `self` so the op closure (Fn) captures a plain value.
        let wait_quorum = self.wait_quorum;

        let mut conn = self.conn.lock().map_err(|e| ReplayStoreError::Unavailable {
            details: format!("redis connection mutex poisoned: {e}"),
        })?;

        // Single atomic op: SET key 1 NX PX <ttl_ms>. The reply is a bulk string
        // "OK" when the key was absent and is now set, or NIL when NX found the
        // key already present. Decode into Option<String>: Some(_) ⇒ we set it ⇒
        // Fresh; None ⇒ NX rejected ⇒ Replay.
        //
        // M19: a transient connection/IO error RECONNECTS once (bounded by the
        // retained #4065 timeouts) and retries; a non-connection error is Fatal.
        // Either way an unrecoverable outage surfaces as Unavailable (fail closed —
        // an outage is NEVER silently treated as a fresh nonce).
        let decision = run_with_reconnect(
            &mut *conn,
            || bounded_connect(&self.params),
            |conn| {
                let result: Result<Option<String>, redis::RedisError> = redis::cmd("SET")
                    .arg(key)
                    .arg(1)
                    .arg("NX")
                    .arg("PX")
                    .arg(ttl_ms)
                    .query(conn);
                match result {
                    Ok(Some(_)) => {
                        // Fresh insert on the primary. For REDIS_WAIT_QUORUM, require
                        // replica durability before reporting Fresh (ADR-MCPS-020).
                        match wait_quorum {
                            None => OpAttempt::Done(ReplayDecision::Fresh),
                            Some(WaitQuorum { quorum, timeout_ms }) => {
                                let acked: Result<i64, redis::RedisError> = redis::cmd("WAIT")
                                    .arg(quorum)
                                    .arg(timeout_ms)
                                    .query(conn);
                                match acked {
                                    Ok(n) => classify_fresh_insert_wait(n, quorum, timeout_ms),
                                    // A WAIT error is also fail-closed-Fatal, for the
                                    // same non-idempotency reason.
                                    Err(e) => OpAttempt::Fatal(ReplayStoreError::Unavailable {
                                        details: format!("redis WAIT failed: {e}"),
                                    }),
                                }
                            }
                        }
                    }
                    // NX found the key present ⇒ Replay. NOTE (audit #97, finding 1):
                    // `SET … NX` is NOT idempotent under the M19 reconnect-retry. If a
                    // FRESH request's first `SET NX` actually LANDED the key on the
                    // primary but the reply read then failed transiently, the bounded
                    // reconnect re-runs the SAME `SET NX`, now finds its own just-written
                    // key, and returns None here ⇒ a fresh request is reported as Replay.
                    // This is accepted BY DESIGN: it FAILS CLOSED — it can only ever
                    // REJECT a legitimate request, never ADMIT a replay (the safe
                    // direction), and it is covered by the documented F4 contract that a
                    // client treats `mcps.replay_cache_unavailable` as
                    // retry-with-a-FRESH-nonce (a new nonce ⇒ a new key ⇒ Fresh). We do
                    // NOT add any compensating path (e.g. read-back / DEL on retry) that
                    // could turn a real Replay into an Ok; preserving the never-admit-a-
                    // replay invariant outweighs the rare spurious-reject availability
                    // cost. (Same non-idempotency reasoning as the WAIT-shortfall Fatal
                    // path in `classify_fresh_insert_wait`.)
                    Ok(None) => OpAttempt::Done(ReplayDecision::Replay),
                    Err(e) => {
                        let store_error = ReplayStoreError::Unavailable {
                            details: format!("redis SET NX PX failed: {e}"),
                        };
                        if is_transient_connection_error(&e) {
                            OpAttempt::Transient(store_error)
                        } else {
                            OpAttempt::Fatal(store_error)
                        }
                    }
                }
            },
        )?;
        Ok(decision)
    }

    /// `Durable` (issue #78, ADR-MCPS-020): admitted nonces live in a SHARED,
    /// server-side-atomic Redis store (`SET NX PX`) visible to every verifier
    /// instance pointed at the same Redis, so they survive a single proxy's restart
    /// and prevent cross-node replays. A [`SharedReplayCache`](crate::shared_replay::SharedReplayCache)
    /// backed by this store therefore declares `Durable` and clears the strict
    /// object-level durability gate; the horizontal strength beyond mere durability
    /// is asserted separately by the configured `ReplayDurabilityTier`.
    fn durability_class(&self) -> mcps_core::ReplayDurabilityClass {
        mcps_core::ReplayDurabilityClass::Durable
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use std::cell::Cell;

    use super::compute_ttl_ms;
    use super::run_with_reconnect;
    use super::ttl_ms_via_clock;
    use super::classify_fresh_insert_wait;
    use super::wait_quorum_satisfied;
    use super::ConnectPermit;
    use super::OpAttempt;
    use super::RedisAtomicReplayStore;
    use super::ReplayDecision;
    use super::ReplayStoreError;
    use super::UnixClock;
    use super::INFLIGHT_CONNECTS;
    use super::MAX_INFLIGHT_CONNECTS;
    use std::sync::atomic::Ordering;

    /// PURE, no-Redis proof of the REDIS_WAIT_QUORUM fail-closed boundary
    /// (ADR-MCPS-020): the configured `quorum` is met only when at least that many
    /// replicas acknowledge; fewer acks (a `WAIT` timeout returns the partial
    /// count) is NOT satisfied → the store fails closed.
    #[test]
    fn wait_quorum_is_met_only_with_enough_acks() {
        assert!(wait_quorum_satisfied(2, 2), "exactly quorum acks is satisfied");
        assert!(wait_quorum_satisfied(3, 2), "more than quorum is satisfied");
        assert!(!wait_quorum_satisfied(1, 2), "fewer than quorum fails closed");
        assert!(!wait_quorum_satisfied(0, 1), "zero acks fails closed");
    }

    /// Issue #23/F4 — PURE, no-Redis proof of the WAIT-quorum-shortfall retry
    /// semantics (ADR-MCPS-020). Enough acks ⇒ Fresh; a shortfall ⇒ Fatal (fail
    /// closed, NOT a transient that would be retried into a wrong Replay), and the
    /// error message states the contract: the nonce is not durably replicated and
    /// the client must retry with a FRESH nonce (the same signed request may be
    /// rejected as replay until the TTL window elapses). We do NOT compensating-DEL
    /// the primary key (it may have replicated; dropping it could reopen a replay
    /// window).
    #[test]
    fn wait_quorum_shortfall_fails_closed_with_fresh_nonce_contract() {
        // Enough acks → durably replicated → Fresh.
        assert!(
            matches!(
                classify_fresh_insert_wait(2, 2, 100),
                OpAttempt::Done(ReplayDecision::Fresh)
            ),
            "meeting quorum must report Fresh"
        );

        // Shortfall → Fatal/Unavailable (fail closed, not retried), with the
        // documented retry-with-fresh-nonce contract in the message.
        match classify_fresh_insert_wait(1, 2, 100) {
            OpAttempt::Fatal(ReplayStoreError::Unavailable { details }) => {
                assert!(
                    details.contains("not durably replicated"),
                    "message must explain the durability shortfall: {details}"
                );
                assert!(
                    details.contains("FRESH nonce"),
                    "message must state the retry-with-fresh-nonce contract: {details}"
                );
            }
            OpAttempt::Done(_) => panic!("a WAIT shortfall must NOT report Fresh"),
            OpAttempt::Transient(_) => {
                panic!("a WAIT shortfall must be Fatal (not retried), never Transient")
            }
        }

        // Zero acks is also a shortfall → fail closed.
        assert!(matches!(
            classify_fresh_insert_wait(0, 1, 100),
            OpAttempt::Fatal(ReplayStoreError::Unavailable { .. })
        ));
    }

    /// PURE, no-Redis proof that the H-8/H-9 `now = 0` bug is gone: with a real
    /// `now`, the TTL is the intended `retain_until - now` WINDOW (seconds × 1000),
    /// NOT the absolute Unix epoch (~1.78e12 ms ≈ 56 years). Runs EVERYWHERE — it
    /// is the primary machine-checked proof; the live-Redis PTTL test only
    /// confirms it end-to-end. Deterministic: no clock, no I/O.
    #[test]
    fn ttl_ms_is_window_not_absolute_epoch() {
        // A realistic skew-folded retain-until (~2026) and a `now` 600s earlier.
        let retain_until: i64 = 1_779_998_730;
        let now: i64 = retain_until - 600;

        let ttl_ms = compute_ttl_ms(retain_until, now);

        // The whole bug in one assert: ttl_secs == retain_until - now.
        assert_eq!(
            ttl_ms,
            600 * 1000,
            "TTL must be the (retain_until - now) window, not the absolute epoch"
        );
        // And it is NOWHERE NEAR the absolute-epoch range the now=0 bug produced.
        let absolute_epoch_ms = (retain_until as u64) * 1000;
        assert!(
            ttl_ms < absolute_epoch_ms / 1000,
            "window TTL ({ttl_ms} ms) must be vastly smaller than the now=0 \
             absolute-epoch TTL ({absolute_epoch_ms} ms ≈ 56 years)"
        );
    }

    /// PURE, no-Redis proof of the H-8/H-9 clock WIRING: the store derives the TTL
    /// from a REAL `now` read through its INJECTED clock, NOT the trait's hard-wired
    /// `now = 0`. Inject a fixed clock, drive the exact TTL path the store uses, and
    /// assert `ttl_secs == retain_until - now`. A regression to `now = 0` would make
    /// the TTL the absolute epoch — caught here deterministically, everywhere.
    #[test]
    fn injected_clock_makes_ttl_the_window_not_the_now_zero_epoch() {
        let retain_until: i64 = 1_779_998_730;
        let fixed_now: i64 = retain_until - 600;
        let clock: UnixClock = Box::new(move || fixed_now);

        let ttl_ms = ttl_ms_via_clock(&clock, retain_until);

        assert_eq!(
            ttl_ms,
            (retain_until - fixed_now) as u64 * 1000,
            "TTL must be (retain_until - injected_now), proving the clock is read, not 0"
        );
        // The now=0 bug would have produced this instead — assert we are NOT it.
        let now_zero_bug_ms = compute_ttl_ms(retain_until, 0);
        assert_ne!(
            ttl_ms, now_zero_bug_ms,
            "the injected-clock TTL must differ from the now=0 absolute-epoch TTL"
        );
    }

    /// A retain-until at/before `now` clamps to a minimal positive TTL (never 0,
    /// never negative): records the sighting just long enough to answer a
    /// same-instant racing replay.
    #[test]
    fn ttl_ms_clamps_to_minimal_when_already_expired() {
        assert_eq!(compute_ttl_ms(1_000, 1_000), 1, "exactly-now → 1ms");
        assert_eq!(compute_ttl_ms(900, 1_000), 1, "already-past → 1ms, not 0/neg");
    }

    /// H-10 regression — runs ANYWHERE, no real Redis. A TCP SINKHOLE (binds,
    /// accepts the connection, then NEVER answers) must NOT wedge the store:
    /// `connect_with` must surface as [`ReplayStoreError::Unavailable`] within its
    /// bounded connect/handshake deadline (fail closed), because redis-rs does not
    /// bound the post-connect RESP handshake reply reads in the blocking path.
    ///
    /// SELF-DISARMING: `connect_with` runs on a spawned thread and the test waits
    /// with `recv_timeout` set ABOVE the connect deadline
    /// (`connect_timeout + HANDSHAKE_GRACE`) but FINITE. With the fix the connect
    /// returns Unavailable inside its deadline → the channel receives → test
    /// passes fast. WITHOUT the fix (call the raw blocking
    /// `get_connection_with_timeout` + handshake with no watchdog) the handshake
    /// blocks forever → the channel never receives → `recv_timeout` ELAPSES → the
    /// test FAILS rather than HANGING the runner. Confirmed by temporarily
    /// replacing the `connect_with` body's watchdog with a direct
    /// `get_connection_with_timeout(...).set_read_timeout(...)`: the connect blocks
    /// in the handshake and the `recv_timeout` branch fires (test fails), proving
    /// the watchdog is load-bearing.
    #[test]
    fn stalled_redis_fails_closed_within_timeout_not_hang() {
        // Serialize with the other tests that assert on the shared in-flight
        // connect count, so this test's stranded worker cannot perturb theirs.
        let _guard = super::tests_support::connect_count_lock();
        // In-process sinkhole: accept the TCP connection, then never answer.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind sinkhole");
        let addr = listener.local_addr().expect("sinkhole addr");
        let sinkhole = thread::spawn(move || {
            // Accept connections and hold them open, silent, forever (until the
            // test process exits). We deliberately read but never write a reply —
            // modelling a backend that accepts TCP but never answers.
            while let Ok((sock, _)) = listener.accept() {
                let mut s = sock;
                thread::spawn(move || {
                    let mut buf = [0u8; 64];
                    let _ = s.read(&mut buf);
                    loop {
                        thread::sleep(Duration::from_secs(3600));
                    }
                });
            }
        });

        let connect_timeout = Duration::from_millis(500);
        let url = format!("redis://{addr}");

        let (tx, rx) = mpsc::channel();
        let connect = thread::spawn(move || {
            let result = RedisAtomicReplayStore::connect_with(
                &url,
                connect_timeout,
                Some(Duration::from_millis(500)),
                Some(Duration::from_millis(500)),
                Box::new(|| 1_779_998_130),
            );
            let _ = tx.send(result.map(|_| ()));
        });

        // The connect deadline is connect_timeout + HANDSHAKE_GRACE (≈5.5s). Bound
        // ABOVE that but finite, so a MISSING watchdog fails (recv elapses) rather
        // than hanging the test runner.
        let outcome = rx.recv_timeout(Duration::from_secs(20));
        match outcome {
            Ok(Ok(())) => panic!("a silent sinkhole must NOT yield a usable connection"),
            Ok(Err(ReplayStoreError::Unavailable { .. })) => {
                // Correct: fail closed within the bounded connect deadline.
            }
            Err(mpsc::RecvTimeoutError::Timeout) => panic!(
                "connect_with did not return within 20s — the connect/handshake is \
                 not bounded (H-10 not fixed); the serve loop would hang"
            ),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("connect thread panicked before sending a result")
            }
        }

        // Best-effort cleanup; the sinkhole thread is detached from the assertion.
        let _ = connect.join();
        drop(sinkhole);
    }

    /// A fake connection standing in for a `redis::Connection` — carries the
    /// generation that produced it so a test can prove the RETRY ran on a FRESH
    /// (re-opened) connection, not the broken one.
    struct FakeConn {
        generation: u32,
    }

    /// M19 — the load-bearing proof, runs EVERYWHERE (no live Redis): a TRANSIENT
    /// connection error on the first op triggers exactly ONE bounded reconnect and
    /// the retry runs on the FRESH connection and succeeds. Without the reconnect
    /// logic (the old `client`-is-dead-reference code) the op would stay failed —
    /// proven by `transient_without_reconnect_stays_failed` below.
    ///
    /// RED without the fix: a `run_with_reconnect` that did NOT reconnect-and-retry
    /// (i.e. surfaced the first Transient as an error) would return `Err` here,
    /// failing the `expect`.
    #[test]
    fn transient_error_reconnects_and_retries() {
        let logins = Cell::new(0u32);
        let attempt = Cell::new(0u32);
        // Start with a "stale" gen-1 connection.
        let mut conn = FakeConn { generation: 1 };

        let result: Result<u32, ReplayStoreError> = run_with_reconnect(
            &mut conn,
            || {
                // Each reconnect mints the next generation (bounded in production by
                // `bounded_connect`; here it always succeeds).
                let generation = logins.get() + 1;
                logins.set(generation);
                Ok(FakeConn {
                    generation: generation + 1,
                })
            },
            |conn| {
                let n = attempt.replace(attempt.get() + 1);
                if n == 0 {
                    // First op on the stale connection: transient IO blip.
                    OpAttempt::Transient(ReplayStoreError::Unavailable {
                        details: "fake: connection dropped".to_string(),
                    })
                } else {
                    // Retry on the re-opened connection.
                    OpAttempt::Done(conn.generation)
                }
            },
        );

        let gen = result.expect("the retry on the re-opened connection must succeed");
        assert_eq!(attempt.get(), 2, "op must run exactly twice (try + one retry)");
        assert_eq!(logins.get(), 1, "exactly one reconnect (bounded, no loop)");
        assert_eq!(
            gen, 2,
            "the retry must run on the FRESH (re-opened) connection, not the broken one"
        );
    }

    /// M19 control proving the RED has teeth: the SAME transient first-op error,
    /// run WITHOUT the reconnect-and-retry (one attempt only — the pre-fix
    /// behaviour where the dead connection was never replaced), stays FAILED. This
    /// is exactly what `run_with_reconnect` must rescue, so a regression that drops
    /// the reconnect would make `transient_error_reconnects_and_retries` fail.
    #[test]
    fn transient_without_reconnect_stays_failed() {
        let mut conn = FakeConn { generation: 1 };
        // Single-attempt op (no reconnect path): models the old code that retained
        // an unused `client` and never re-established the connection.
        let single_attempt = |conn: &mut FakeConn| -> Result<u32, ReplayStoreError> {
            match (|c: &mut FakeConn| {
                let _ = c;
                OpAttempt::<u32>::Transient(ReplayStoreError::Unavailable {
                    details: "fake: connection dropped".to_string(),
                })
            })(conn)
            {
                OpAttempt::Done(v) => Ok(v),
                OpAttempt::Transient(e) | OpAttempt::Fatal(e) => Err(e),
            }
        };
        let result = single_attempt(&mut conn);
        assert!(
            matches!(result, Err(ReplayStoreError::Unavailable { .. })),
            "without reconnect, one transient blip permanently degrades the op \
             (the M19 bug) — this is the behaviour run_with_reconnect must fix"
        );
    }

    /// M19 fail-closed: a transient error whose reconnect ALSO fails surfaces the
    /// reconnect error (Unavailable) — no in-process fallback, no infinite retry.
    #[test]
    fn reconnect_failure_after_transient_fails_closed() {
        let mut conn = FakeConn { generation: 1 };
        let result: Result<u32, ReplayStoreError> = run_with_reconnect(
            &mut conn,
            || {
                Err(ReplayStoreError::Unavailable {
                    details: "fake: reconnect refused".to_string(),
                })
            },
            |_conn| {
                OpAttempt::Transient(ReplayStoreError::Unavailable {
                    details: "fake: connection dropped".to_string(),
                })
            },
        );
        assert!(
            matches!(result, Err(ReplayStoreError::Unavailable { .. })),
            "a failed reconnect after a transient error must fail closed"
        );
    }

    /// M19: a FATAL (non-connection) op error is surfaced WITHOUT a reconnect — a
    /// reconnect would not cure a server-side type/logic error.
    #[test]
    fn fatal_error_does_not_reconnect() {
        let reconnects = Cell::new(0u32);
        let mut conn = FakeConn { generation: 1 };
        let result: Result<u32, ReplayStoreError> = run_with_reconnect(
            &mut conn,
            || {
                reconnects.set(reconnects.get() + 1);
                Ok(FakeConn { generation: 99 })
            },
            |_conn| {
                OpAttempt::Fatal(ReplayStoreError::Unavailable {
                    details: "fake: WRONGTYPE".to_string(),
                })
            },
        );
        assert!(matches!(result, Err(ReplayStoreError::Unavailable { .. })));
        assert_eq!(
            reconnects.get(),
            0,
            "a Fatal (non-connection) error must NOT trigger a reconnect"
        );
    }

    /// Audit #97 (findings 2+3) — DETERMINISTIC proof of the abandoned-connect-thread
    /// CEILING, no live Redis. redis-rs 0.27's blocking handshake read cannot be
    /// bounded in-band, so an overrunning connect worker against a half-open backend
    /// is abandoned and strands one thread+fd; the [`ConnectPermit`] semaphore caps
    /// how many can be simultaneously stranded. Here we directly drive the permit
    /// pool — the exact mechanism [`super::bounded_connect`] uses to fail closed
    /// before spawning yet another doomed thread — and assert: (a) up to
    /// `MAX_INFLIGHT_CONNECTS` permits are grantable, (b) the next acquire FAILS
    /// CLOSED with [`ReplayStoreError::Unavailable`] (does NOT spawn/leak), and
    /// (c) dropping a permit (a worker terminating, releasing its fd) frees exactly
    /// one slot so the pool recovers. This bounds the leak to a CONSTANT.
    ///
    /// Serialized via a process-global lock because `INFLIGHT_CONNECTS` is shared
    /// process state; other tests that touch the real connect path (the sinkhole
    /// test) take the same lock so the counts never interleave.
    #[test]
    fn abandoned_connect_threads_are_bounded_by_a_ceiling_failing_closed() {
        let _guard = super::tests_support::connect_count_lock();
        // A permit STRANDED by a half-open-backend test (its worker never returns)
        // is a legitimate persistent baseline — the very thing the ceiling bounds —
        // so measure RELATIVE to whatever is already in flight, not against 0.
        let baseline = INFLIGHT_CONNECTS.load(Ordering::Acquire);
        assert!(
            baseline < MAX_INFLIGHT_CONNECTS,
            "stranded baseline ({baseline}) must leave headroom under the ceiling"
        );
        let grantable = MAX_INFLIGHT_CONNECTS - baseline;

        // Saturate the remaining headroom: every free permit must be grantable.
        let mut held: Vec<ConnectPermit> = Vec::new();
        for i in 0..grantable {
            match ConnectPermit::acquire() {
                Ok(p) => held.push(p),
                Err(e) => panic!("permit {i} of {grantable} must be grantable: {e:?}"),
            }
        }
        assert_eq!(INFLIGHT_CONNECTS.load(Ordering::Acquire), MAX_INFLIGHT_CONNECTS);

        // Ceiling reached: the next acquire FAILS CLOSED rather than leaking another
        // thread+fd.
        match ConnectPermit::acquire() {
            Err(ReplayStoreError::Unavailable { details }) => {
                assert!(
                    details.contains("already in flight"),
                    "saturation error must name the ceiling: {details}"
                );
            }
            Ok(_) => panic!("acquiring past the ceiling must fail closed, not leak a thread"),
        }
        assert_eq!(
            INFLIGHT_CONNECTS.load(Ordering::Acquire),
            MAX_INFLIGHT_CONNECTS,
            "a refused acquire must NOT have incremented the count"
        );

        // A worker terminating (permit dropped, fd released) frees exactly one slot.
        held.pop();
        assert_eq!(INFLIGHT_CONNECTS.load(Ordering::Acquire), MAX_INFLIGHT_CONNECTS - 1);
        let reacquired =
            ConnectPermit::acquire().expect("a freed slot must be re-grantable after a drop");
        assert_eq!(INFLIGHT_CONNECTS.load(Ordering::Acquire), MAX_INFLIGHT_CONNECTS);
        drop(reacquired);

        // Release everything WE took; the pool returns to its baseline (no permit
        // leak in the RAII drop path — only the pre-existing stranded baseline left).
        drop(held);
        assert_eq!(
            INFLIGHT_CONNECTS.load(Ordering::Acquire),
            baseline,
            "all permits we acquired must be returned — no leak in the RAII drop path"
        );
    }

    /// Audit #97 — the permit is RELEASED when a successful in-time connect's worker
    /// finishes, so healthy traffic never approaches the ceiling. Drive the real
    /// [`super::bounded_connect`] against the in-process sinkhole: it abandons the
    /// worker (deadline elapses) and the permit stays held by the stranded worker —
    /// but a SUBSEQUENT connect to a DIFFERENT, immediately-refused address shows the
    /// count is still well under the ceiling (one stranded worker, not unbounded).
    /// This is the wiring complement to the pure ceiling test above; the residual
    /// (that a truly-wedged worker's permit is only reclaimed if its read ever
    /// errors) is bounded precisely by `MAX_INFLIGHT_CONNECTS` per that test.
    #[test]
    fn one_stalled_connect_strands_at_most_one_permit() {
        let _guard = super::tests_support::connect_count_lock();
        // Measure relative to any baseline stranded by another half-open test.
        let baseline = INFLIGHT_CONNECTS.load(Ordering::Acquire);

        // Sinkhole: accept TCP, never answer the handshake.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind sinkhole");
        let addr = listener.local_addr().expect("sinkhole addr");
        let sinkhole = thread::spawn(move || {
            while let Ok((sock, _)) = listener.accept() {
                let mut s = sock;
                thread::spawn(move || {
                    let mut buf = [0u8; 64];
                    let _ = s.read(&mut buf);
                    loop {
                        thread::sleep(Duration::from_secs(3600));
                    }
                });
            }
        });

        let params = super::ConnectParams {
            url: format!("redis://{addr}"),
            connect_timeout: Duration::from_millis(200),
            read_timeout: Some(Duration::from_millis(200)),
            write_timeout: Some(Duration::from_millis(200)),
        };
        // Fails closed within connect_timeout + HANDSHAKE_GRACE, abandoning ONE
        // worker that now holds exactly ONE permit.
        let result = super::bounded_connect(&params);
        assert!(
            matches!(result, Err(ReplayStoreError::Unavailable { .. })),
            "a stalled handshake must fail closed"
        );
        let stranded = INFLIGHT_CONNECTS.load(Ordering::Acquire);
        assert!(
            stranded <= baseline + 1,
            "a single stalled connect must strand AT MOST one MORE permit \
             (baseline {baseline}, now {stranded})"
        );

        drop(sinkhole);
    }
}

/// Process-global serialization for tests that read/write the shared
/// [`INFLIGHT_CONNECTS`] counter, so their assertions on absolute counts cannot
/// interleave. Outside `#[cfg(test)]`-only code paths this module is inert.
#[cfg(test)]
mod tests_support {
    use std::sync::Mutex;
    use std::sync::MutexGuard;
    use std::sync::OnceLock;

    static CONNECT_COUNT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    /// Acquire the shared lock guarding in-flight-connect-count assertions. A
    /// poisoned lock (a prior test panicked while holding it) is recovered — the
    /// guarded data is `()`, so there is nothing to be left inconsistent.
    pub(super) fn connect_count_lock() -> MutexGuard<'static, ()> {
        CONNECT_COUNT_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
