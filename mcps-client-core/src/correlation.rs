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

use mcps_core::McpsError;
use std::collections::HashMap;

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

    /// Cancel an outstanding request, returning its entry if present. The nonce
    /// stays in the window until swept (cancelling does not re-open replay).
    pub fn cancel(&mut self, correlation_id: &str) -> Option<PendingRequest> {
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
