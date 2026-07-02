//! In-flight request correlation store (MCPS-47, #194; ADR-MCPS-044 §In-flight
//! correlation state; CONTEXT.md §In-flight correlation state).
//!
//! "Stateless-primary" means NO discovery-session state — it does NOT mean no
//! in-flight state. A client/proxy that signs requests and verifies the bound
//! responses MUST remember, per OUTSTANDING request, everything needed to bind the
//! response and reject replays: the correlation id, request hash, nonce, issue
//! time, deadline, route, audience, expected signer set, version/canonicalization,
//! and the authorization digest.
//!
//! Lifecycle (CONTEXT.md): an entry is retained until the response verifies, the
//! request is cancelled, or the deadline passes. Cleanup happens on completion AND
//! via a periodic expiry sweep. A response that arrives AFTER its entry was cleaned
//! up is **uncorrelatable** and fails closed — it can never be bound to a known
//! request hash, so it is never accepted "on faith". A nonce may not be reused
//! while a prior use is still within its freshness window.
//!
//! This module is pure: it takes the current time (`now_unix`) as a parameter and
//! owns no clock. The mode-specific layer drives `sweep_expired` on a timer and
//! supplies wall-clock time.

use mcps_core::build_mcp_mrt_continuation;
use mcps_core::Continuation;
use mcps_core::McpsError;
use std::collections::HashMap;

/// The non-terminal record retained when a verified `InputRequiredResult` is
/// correlated (ADR-MCPS-047 / D7 — "associate-without-consume").
///
/// The original request's response slot IS consumed (the `InputRequiredResult`
/// arrived and verified), but the multi-round-trip stays associated: the client
/// keeps the linkage needed to build the signed continuation and to reconcile the
/// exchange. Its `nonce` remains reserved in the store's nonce window (a
/// continuation uses a FRESH nonce). Swept on deadline like any other entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputRequiredRecord {
    /// `request_hash` of the request that produced the `InputRequiredResult` — the
    /// continuation's `previous_request_hash` (ADR-MCPS-047 / D4).
    pub previous_request_hash: String,
    /// Hash of the verified `InputRequiredResult` response preimage — the
    /// continuation's `input_required_response_hash` (D4).
    pub input_required_response_hash: String,
    /// Deadline (unix seconds) inherited from the original request; the exchange
    /// expires here if no continuation completes it.
    pub deadline_unix: i64,
    /// Route id the original request was sent on (the continuation reuses it).
    pub route_id: String,
    /// Resolved audience (the continuation targets the same verifier).
    pub audience: String,
    /// Signer identities a valid continuation response may carry.
    pub expected_server_signers: Vec<String>,
}

/// Everything retained for one outstanding request, captured at send time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRequest {
    /// The client-chosen correlation id (e.g. the JSON-RPC id or a fresh handle).
    pub correlation_id: String,
    /// `sha256:<b64url>` of the signed request preimage — the response-binding handle.
    pub request_hash: String,
    /// The anti-replay nonce carried in the request envelope.
    pub nonce: String,
    /// Issue time (unix seconds).
    pub issued_at_unix: i64,
    /// Deadline (unix seconds) after which the entry expires and a response is late.
    pub deadline_unix: i64,
    /// The route id this request was sent on.
    pub route_id: String,
    /// The resolved audience (verifier identity).
    pub audience: String,
    /// The signer identities a valid response may carry (MCPS-43 binding).
    pub expected_server_signers: Vec<String>,
    /// The envelope `version` (`draft-02`).
    pub version: String,
    /// The protected `canonicalization_id` bound by the request (response must match).
    pub canonicalization_id: String,
    /// The authorization-binding digest value bound into the request.
    pub authz_digest: String,
}

/// A correlation-store failure. Each maps to a frozen wire reason (MCPS-48) so the
/// client error vocabulary never forks from `mcps-core`'s taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelationError {
    /// The correlation id is already registered (an outstanding-id collision).
    DuplicateCorrelationId,
    /// The nonce was already used within its freshness window (reuse/replay).
    NonceReuse,
    /// No pending entry matches — a late response after cleanup, or an unknown id.
    /// Fails closed: the response cannot be bound to any in-flight request.
    Uncorrelatable,
    /// The pending entry exists but its deadline has passed.
    Expired,
}

impl CorrelationError {
    /// Map this local correlation failure to the frozen `mcps-core` wire taxonomy
    /// (MCPS-48): the client never invents a parallel wire reason. A duplicate id or
    /// nonce reuse is a replay ([`McpsError::ReplayDetected`]); an uncorrelatable
    /// (late-after-cleanup) response cannot be bound to any request, a response-
    /// binding failure ([`McpsError::ResponseHashMismatch`]); an expired entry is
    /// [`McpsError::ExpiredRequest`].
    pub fn to_mcps_error(self) -> McpsError {
        match self {
            CorrelationError::DuplicateCorrelationId | CorrelationError::NonceReuse => {
                McpsError::ReplayDetected
            }
            CorrelationError::Uncorrelatable => McpsError::ResponseHashMismatch,
            CorrelationError::Expired => McpsError::ExpiredRequest,
        }
    }
}

/// Per-outstanding-request correlation store with nonce-reuse prevention and an
/// expiry sweep. Keyed by correlation id; a separate nonce→deadline window guards
/// replay within the freshness window.
#[derive(Debug, Default)]
pub struct CorrelationStore {
    pending: HashMap<String, PendingRequest>,
    /// nonce -> the deadline until which it is considered "within window".
    nonce_window: HashMap<String, i64>,
    /// Non-terminal multi-round-trip records (ADR-MCPS-047 / D7): correlation id ->
    /// the verified `InputRequiredResult` linkage awaiting a signed continuation.
    non_terminal: HashMap<String, InputRequiredRecord>,
}

impl CorrelationStore {
    /// An empty store.
    pub fn new() -> Self {
        CorrelationStore::default()
    }

    /// The number of currently-outstanding requests.
    pub fn outstanding(&self) -> usize {
        self.pending.len()
    }

    /// The number of non-terminal multi-round-trip records awaiting a continuation
    /// (ADR-MCPS-047 / D7).
    pub fn non_terminal_outstanding(&self) -> usize {
        self.non_terminal.len()
    }

    /// The retained non-terminal record for `correlation_id`, if the exchange is
    /// awaiting a signed continuation (ADR-MCPS-047 / D7).
    pub fn input_required(&self, correlation_id: &str) -> Option<&InputRequiredRecord> {
        self.non_terminal.get(correlation_id)
    }

    /// Register an outstanding request at `now_unix`.
    ///
    /// Fails closed on a duplicate correlation id, or if the nonce is still within
    /// a prior use's window ([`CorrelationError::NonceReuse`]). A nonce whose prior
    /// window has elapsed (deadline `<= now`) may be reused — the freshness window
    /// has closed.
    pub fn register(
        &mut self,
        request: PendingRequest,
        now_unix: i64,
    ) -> Result<(), CorrelationError> {
        if self.pending.contains_key(&request.correlation_id) {
            return Err(CorrelationError::DuplicateCorrelationId);
        }
        if let Some(&retained_until) = self.nonce_window.get(&request.nonce) {
            if retained_until > now_unix {
                return Err(CorrelationError::NonceReuse);
            }
        }
        self.nonce_window
            .insert(request.nonce.clone(), request.deadline_unix);
        self.pending.insert(request.correlation_id.clone(), request);
        Ok(())
    }

    /// Correlate an incoming response by `correlation_id` at `now_unix`, removing
    /// and returning the pending entry on success (cleanup-on-completion).
    ///
    /// Fails closed with [`CorrelationError::Uncorrelatable`] when no entry matches
    /// (a late response after cleanup, or an unknown id), or
    /// [`CorrelationError::Expired`] when the entry exists but its deadline passed.
    /// The nonce stays in the window until swept, so completion does not re-open it
    /// to replay.
    pub fn take_for_response(
        &mut self,
        correlation_id: &str,
        now_unix: i64,
    ) -> Result<PendingRequest, CorrelationError> {
        match self.pending.get(correlation_id) {
            None => Err(CorrelationError::Uncorrelatable),
            Some(entry) if now_unix > entry.deadline_unix => {
                // Past deadline: remove it and report expired (it is also swept).
                self.pending.remove(correlation_id);
                Err(CorrelationError::Expired)
            }
            Some(_) => Ok(self
                .pending
                .remove(correlation_id)
                .expect("present by the match above")),
        }
    }

    /// Read an outstanding request's retained state WITHOUT consuming it, applying
    /// the same existence + deadline gate as [`take_for_response`](Self::take_for_response).
    ///
    /// The multi-round-trip flow (ADR-MCPS-047) needs the expected `request_hash`
    /// BEFORE it can classify the response as terminal vs `InputRequiredResult` — but
    /// it must not consume the slot until that decision is made (a terminal response
    /// consumes via `take_for_response`; a non-terminal one via `record_input_required`).
    /// A past-deadline entry is removed and reported [`CorrelationError::Expired`],
    /// exactly like `take_for_response`; on success the entry stays in place.
    pub fn peek_for_response(
        &mut self,
        correlation_id: &str,
        now_unix: i64,
    ) -> Result<PendingRequest, CorrelationError> {
        match self.pending.get(correlation_id) {
            None => Err(CorrelationError::Uncorrelatable),
            Some(entry) if now_unix > entry.deadline_unix => {
                self.pending.remove(correlation_id);
                Err(CorrelationError::Expired)
            }
            Some(entry) => Ok(entry.clone()),
        }
    }

    /// Correlate a verified, NON-TERMINAL `InputRequiredResult` for `correlation_id`
    /// (ADR-MCPS-047 / D7 — associate-without-consume). Same existence + deadline
    /// gate as [`take_for_response`](Self::take_for_response), but instead of
    /// completing the exchange it:
    ///
    /// - consumes the original request's response slot (the `InputRequiredResult`
    ///   arrived and verified — a second response for the same id must not correlate);
    /// - retains an [`InputRequiredRecord`] linking the exchange, keyed by the same
    ///   correlation id, so the client can look up the linkage and sweep it; and
    /// - returns the typed [`Continuation`] binding (`previous_request_hash` = the
    ///   original request hash, `input_required_response_hash` = the verified
    ///   response preimage hash) to feed into the signed continuation request.
    ///
    /// The original nonce stays reserved in the window (the continuation MUST use a
    /// fresh nonce). Caller MUST pass the hash of the ALREADY-VERIFIED response
    /// preimage ([`mcps_core::response_hash`]); this store binds, it does not verify.
    pub fn record_input_required(
        &mut self,
        correlation_id: &str,
        input_required_response_hash: impl Into<String>,
        now_unix: i64,
    ) -> Result<Continuation, CorrelationError> {
        let entry = match self.pending.get(correlation_id) {
            None => return Err(CorrelationError::Uncorrelatable),
            Some(entry) if now_unix > entry.deadline_unix => {
                self.pending.remove(correlation_id);
                return Err(CorrelationError::Expired);
            }
            Some(entry) => entry,
        };
        let input_required_response_hash = input_required_response_hash.into();
        let record = InputRequiredRecord {
            previous_request_hash: entry.request_hash.clone(),
            input_required_response_hash: input_required_response_hash.clone(),
            deadline_unix: entry.deadline_unix,
            route_id: entry.route_id.clone(),
            audience: entry.audience.clone(),
            expected_server_signers: entry.expected_server_signers.clone(),
        };
        let continuation = build_mcp_mrt_continuation(
            record.previous_request_hash.clone(),
            input_required_response_hash,
        );
        // Consume the original response slot; keep the exchange associated.
        self.pending.remove(correlation_id);
        self.non_terminal.insert(correlation_id.to_string(), record);
        Ok(continuation)
    }

    /// Cancel an outstanding request, returning its entry if present. Also drops any
    /// non-terminal multi-round-trip record for the same id. The nonce stays in the
    /// window until swept (cancelling does not re-open replay).
    pub fn cancel(&mut self, correlation_id: &str) -> Option<PendingRequest> {
        self.non_terminal.remove(correlation_id);
        self.pending.remove(correlation_id)
    }

    /// Periodic expiry sweep at `now_unix`: drop pending entries past their
    /// deadline and evict nonce-window entries whose window has closed. Returns the
    /// number of pending entries removed. After a nonce's window is evicted it may
    /// be reused.
    pub fn sweep_expired(&mut self, now_unix: i64) -> usize {
        let before = self.pending.len();
        self.pending
            .retain(|_, entry| entry.deadline_unix >= now_unix);
        self.nonce_window
            .retain(|_, &mut retained_until| retained_until >= now_unix);
        // Non-terminal MRT records expire on the same inherited deadline: an
        // exchange with no completed continuation must not linger.
        self.non_terminal
            .retain(|_, record| record.deadline_unix >= now_unix);
        before - self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(correlation_id: &str, nonce: &str, deadline: i64) -> PendingRequest {
        PendingRequest {
            correlation_id: correlation_id.to_string(),
            request_hash: "sha256:AAAA".to_string(),
            nonce: nonce.to_string(),
            issued_at_unix: 1000,
            deadline_unix: deadline,
            route_id: "route-a".to_string(),
            audience: "did:example:server".to_string(),
            expected_server_signers: vec!["did:example:server".to_string()],
            version: "draft-02".to_string(),
            canonicalization_id: "mcps-jcs-int53-json-v1".to_string(),
            authz_digest: "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o".to_string(),
        }
    }

    #[test]
    fn register_and_correlate_round_trip() {
        let mut store = CorrelationStore::new();
        store.register(pending("c1", "n1", 2000), 1000).unwrap();
        assert_eq!(store.outstanding(), 1);
        let taken = store.take_for_response("c1", 1500).unwrap();
        assert_eq!(taken.request_hash, "sha256:AAAA");
        assert_eq!(store.outstanding(), 0);
    }

    #[test]
    fn duplicate_correlation_id_fails_closed() {
        let mut store = CorrelationStore::new();
        store.register(pending("c1", "n1", 2000), 1000).unwrap();
        assert_eq!(
            store.register(pending("c1", "n2", 2000), 1000).unwrap_err(),
            CorrelationError::DuplicateCorrelationId
        );
    }

    #[test]
    fn nonce_reuse_within_window_is_rejected() {
        let mut store = CorrelationStore::new();
        store
            .register(pending("c1", "shared-nonce", 2000), 1000)
            .unwrap();
        // Same nonce, different request, still within the window -> reuse.
        assert_eq!(
            store
                .register(pending("c2", "shared-nonce", 2000), 1500)
                .unwrap_err(),
            CorrelationError::NonceReuse
        );
    }

    #[test]
    fn nonce_reusable_after_window_closes() {
        let mut store = CorrelationStore::new();
        store
            .register(pending("c1", "shared-nonce", 2000), 1000)
            .unwrap();
        store.take_for_response("c1", 1500).unwrap();
        // Sweep past the window so the nonce is evicted.
        store.sweep_expired(2001);
        // Now the nonce can be reused (window closed).
        assert!(store
            .register(pending("c2", "shared-nonce", 3000), 2001)
            .is_ok());
    }

    #[test]
    fn late_response_after_cleanup_is_uncorrelatable() {
        let mut store = CorrelationStore::new();
        store.register(pending("c1", "n1", 2000), 1000).unwrap();
        // The entry expires and is swept.
        let removed = store.sweep_expired(2001);
        assert_eq!(removed, 1);
        // A response arriving now cannot be correlated -> fail closed.
        assert_eq!(
            store.take_for_response("c1", 2002).unwrap_err(),
            CorrelationError::Uncorrelatable
        );
    }

    #[test]
    fn response_past_deadline_is_expired() {
        let mut store = CorrelationStore::new();
        store.register(pending("c1", "n1", 2000), 1000).unwrap();
        // Entry still present (no sweep yet) but now is past the deadline.
        assert_eq!(
            store.take_for_response("c1", 2001).unwrap_err(),
            CorrelationError::Expired
        );
        // And it was removed by the attempt.
        assert_eq!(store.outstanding(), 0);
    }

    #[test]
    fn unknown_correlation_id_is_uncorrelatable() {
        let mut store = CorrelationStore::new();
        assert_eq!(
            store.take_for_response("nope", 1000).unwrap_err(),
            CorrelationError::Uncorrelatable
        );
    }

    #[test]
    fn cancel_removes_the_entry() {
        let mut store = CorrelationStore::new();
        store.register(pending("c1", "n1", 2000), 1000).unwrap();
        assert!(store.cancel("c1").is_some());
        assert_eq!(store.outstanding(), 0);
        assert_eq!(
            store.take_for_response("c1", 1500).unwrap_err(),
            CorrelationError::Uncorrelatable
        );
    }

    #[test]
    fn input_required_associates_without_completing_and_returns_binding() {
        let mut store = CorrelationStore::new();
        // Register with a known request_hash to check the continuation binding.
        let mut p = pending("c1", "n1", 2000);
        p.request_hash = "sha256:PREVIOUSAAAA".to_string();
        store.register(p, 1000).unwrap();

        let cont = store
            .record_input_required("c1", "sha256:RESP1BBBB", 1500)
            .unwrap();
        // The binding ties the original request hash to the verified response hash.
        assert_eq!(
            cont,
            mcps_core::Continuation::McpMrt {
                previous_request_hash: "sha256:PREVIOUSAAAA".to_string(),
                input_required_response_hash: "sha256:RESP1BBBB".to_string(),
            }
        );
        // The original response slot is consumed, but the exchange stays associated.
        assert_eq!(store.outstanding(), 0);
        assert_eq!(store.non_terminal_outstanding(), 1);
        let rec = store.input_required("c1").expect("retained");
        assert_eq!(rec.input_required_response_hash, "sha256:RESP1BBBB");
    }

    #[test]
    fn peek_reads_without_consuming() {
        let mut store = CorrelationStore::new();
        let mut p = pending("c1", "n1", 2000);
        p.request_hash = "sha256:PEEKME".to_string();
        store.register(p, 1000).unwrap();
        // Peek twice: both succeed and the entry stays outstanding.
        assert_eq!(
            store.peek_for_response("c1", 1500).unwrap().request_hash,
            "sha256:PEEKME"
        );
        assert_eq!(
            store.peek_for_response("c1", 1500).unwrap().request_hash,
            "sha256:PEEKME"
        );
        assert_eq!(store.outstanding(), 1);
        // A real consume still works afterward.
        assert!(store.take_for_response("c1", 1500).is_ok());
        assert_eq!(store.outstanding(), 0);
    }

    #[test]
    fn peek_unknown_is_uncorrelatable_and_expired_is_removed() {
        let mut store = CorrelationStore::new();
        assert_eq!(
            store.peek_for_response("nope", 1000).unwrap_err(),
            CorrelationError::Uncorrelatable
        );
        store.register(pending("c1", "n1", 2000), 1000).unwrap();
        assert_eq!(
            store.peek_for_response("c1", 2001).unwrap_err(),
            CorrelationError::Expired
        );
        assert_eq!(store.outstanding(), 0);
    }

    #[test]
    fn second_response_after_input_required_is_uncorrelatable() {
        let mut store = CorrelationStore::new();
        store.register(pending("c1", "n1", 2000), 1000).unwrap();
        store
            .record_input_required("c1", "sha256:RESP", 1500)
            .unwrap();
        // The slot was consumed; a stray terminal response for the same id fails closed.
        assert_eq!(
            store.take_for_response("c1", 1600).unwrap_err(),
            CorrelationError::Uncorrelatable
        );
    }

    #[test]
    fn input_required_original_nonce_stays_reserved() {
        let mut store = CorrelationStore::new();
        store.register(pending("c1", "shared", 2000), 1000).unwrap();
        store
            .record_input_required("c1", "sha256:RESP", 1500)
            .unwrap();
        // A continuation MUST use a fresh nonce; reusing the original within window fails.
        assert_eq!(
            store
                .register(pending("c2", "shared", 2000), 1600)
                .unwrap_err(),
            CorrelationError::NonceReuse
        );
    }

    #[test]
    fn input_required_on_unknown_id_is_uncorrelatable() {
        let mut store = CorrelationStore::new();
        assert_eq!(
            store
                .record_input_required("nope", "sha256:RESP", 1000)
                .unwrap_err(),
            CorrelationError::Uncorrelatable
        );
    }

    #[test]
    fn input_required_past_deadline_is_expired() {
        let mut store = CorrelationStore::new();
        store.register(pending("c1", "n1", 2000), 1000).unwrap();
        assert_eq!(
            store
                .record_input_required("c1", "sha256:RESP", 2001)
                .unwrap_err(),
            CorrelationError::Expired
        );
    }

    #[test]
    fn sweep_drops_expired_non_terminal_records() {
        let mut store = CorrelationStore::new();
        store.register(pending("c1", "n1", 1500), 1000).unwrap();
        store
            .record_input_required("c1", "sha256:RESP", 1200)
            .unwrap();
        assert_eq!(store.non_terminal_outstanding(), 1);
        // Past the inherited deadline (1500), the non-terminal record is swept.
        store.sweep_expired(2000);
        assert_eq!(store.non_terminal_outstanding(), 0);
    }

    #[test]
    fn sweep_removes_only_expired_entries() {
        let mut store = CorrelationStore::new();
        store.register(pending("c1", "n1", 1500), 1000).unwrap();
        store.register(pending("c2", "n2", 3000), 1000).unwrap();
        // At t=2000, c1 (deadline 1500) is expired; c2 (3000) survives.
        assert_eq!(store.sweep_expired(2000), 1);
        assert_eq!(store.outstanding(), 1);
        assert!(store.take_for_response("c2", 2000).is_ok());
    }
}
