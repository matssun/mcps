//! PKCS#11-backed response-signing [`KeySource`] — the real, non-exporting
//! backend behind the issue #3838 delegation seam (issue #4034).
//!
//! # What this delivers
//! A vendor-neutral [`Pkcs11KeySource`] that drives the proxy's full
//! response-signing path while the Ed25519 **response-signing private key never
//! leaves the token**. It speaks standard PKCS#11 (Cryptoki v2.40+ `CKM_EDDSA`)
//! through a small OWNED safe wrapper ([`crate::pkcs11_native`]) over the raw
//! `cryptoki-sys` FFI bindings — the high-level `cryptoki` crate was dropped
//! because it transitively pulled the UNMAINTAINED `paste` crate
//! (RUSTSEC-2024-0436). It references NO host security system — it is tested
//! against an INDEPENDENT [SoftHSM2] token (see
//! `tests/pkcs11_keysource_e2e_test.rs` for the `softhsm2-util` provisioning
//! commands).
//!
//! The private key is located ON the token by label and used ONLY via `C_Sign`
//! with `CKM_EDDSA`; the 64-byte raw Ed25519 signature comes back from the
//! device and is Base64URL-no-pad encoded to match exactly what
//! [`SigningKey::sign`](mcps_core::SigningKey::sign) produces, so a signature it
//! makes verifies under [`response_public_key`](ResponseSigner::response_public_key)
//! with no special-casing on the verifier side. The PUBLIC key IS exportable even
//! from a non-exporting token (it is what relying parties verify against), so its
//! raw 32-byte Edwards point is read via `CKA_EC_POINT`.
//!
//! # TLS material (scope)
//! This source holds an inner [`FileKeySource`] for the TLS server certificate
//! chain, TLS server private key, and client-CA trust anchors: in THIS change the
//! token custodies ONLY the response-signing key, and the TLS cert/key/CA still
//! come from files. Delegated TLS signing — fronting the token behind a custom
//! [`rustls::sign::SigningKey`] so the TLS private key also never leaves the
//! device — is the remaining OUT-OF-SCOPE sub-item of #4034 and is deliberately
//! NOT implemented here; the existing file-backed TLS path is reused unchanged.
//!
//! # Fail-closed posture
//! Every Cryptoki/library failure (module load, slot/token selection, login,
//! object lookup, sign, attribute read, malformed key bytes) maps to a
//! [`KeyError::NotFound`]/[`KeyError::Malformed`] with context. There is no
//! panic, no fallback to an in-process key, and never a fabricated signature on
//! any error path.
//!
//! This entire module compiles ONLY under the non-default `pkcs11_keysource`
//! cargo feature, so a default build is byte-for-byte unchanged and gains zero
//! dependencies.
//!
//! [SoftHSM2]: https://github.com/opendnssec/SoftHSMv2

use std::sync::Mutex;

use cryptoki_sys::CK_OBJECT_HANDLE;
use cryptoki_sys::CK_SESSION_HANDLE;
use cryptoki_sys::CK_SLOT_ID;
use cryptoki_sys::CKR_DEVICE_ERROR;
use cryptoki_sys::CKR_DEVICE_REMOVED;
use cryptoki_sys::CKR_SESSION_CLOSED;
use cryptoki_sys::CKR_SESSION_COUNT;
use cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
use cryptoki_sys::CKR_USER_NOT_LOGGED_IN;
use mcps_core::b64url_encode;
use mcps_core::VerificationKey;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use zeroize::Zeroizing;

use crate::key_source::FileKeySource;
use crate::key_source::KeyError;
use crate::key_source::KeySource;
use crate::key_source::ResponseSigner;
use crate::pkcs11_native::AttributeTemplate;
use crate::pkcs11_native::ObjectClass;
use crate::pkcs11_native::Pkcs11Context;
use crate::pkcs11_native::Pkcs11Error;
use crate::pkcs11_native::SessionCloser;
use crate::pkcs11_native::SessionRef;

/// Raw Ed25519 public-key length (the Edwards point), in bytes.
const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// Raw Ed25519 signature length, in bytes.
const ED25519_SIGNATURE_LEN: usize = 64;

/// Outcome of running an operation on a (possibly stale) cached session.
///
/// The amortization layer ([`AmortizedSession`]) distinguishes a *transient*
/// session fault (the cached session went invalid/closed or login lapsed —
/// re-open ONCE and retry) from a *fatal* error (a genuine
/// [`KeyError`] that re-opening would not fix — propagate, fail closed). This is
/// what keeps the fail-closed posture intact while still amortizing logins: a real
/// signing/lookup failure is NEVER masked by a reconnect-and-retry loop.
enum SessionOpError {
    /// The cached session is no longer usable (handle invalid / closed / not
    /// logged in / device hiccup). Re-open a fresh logged-in session and retry the
    /// operation exactly once.
    SessionInvalid(KeyError),
    /// A genuine failure that a fresh session would not cure — propagate as-is.
    Fatal(KeyError),
}

/// Open a fresh logged-in session of type `S`. Implemented for the real
/// [`Pkcs11KeySource`] (opens a Cryptoki R/W session + `C_Login`) and, in tests,
/// by a counting fake — so the amortization decision is provable WITHOUT a live
/// token (no SoftHSM dependency for the unit proof).
trait LoginSessionFactory {
    /// The session handle type this factory produces.
    type Session;
    /// Open a NEW session and authenticate it (one `C_Login`). Every call here is
    /// one login — the whole point of [`AmortizedSession`] is to make this run far
    /// fewer than once per signed response.
    fn open_logged_in(&self) -> Result<Self::Session, KeyError>;
}

/// Amortizes the PKCS#11 LOGIN across operations (audit M16): instead of opening a
/// fresh session and performing a `C_Login` on EVERY signed response — which makes
/// signing latency/availability hostage to token login throughput and is a
/// boundary DoS amplification — this holds ONE logged-in session behind a `Mutex`
/// and reuses it. A fresh login happens only on first use or when the cached
/// session has gone invalid (handle closed / token re-inserted / login lapsed), so
/// N sequential signs perform far fewer than N logins.
///
/// Fail-closed is preserved: a *fatal* [`SessionOpError::Fatal`] (a real sign /
/// lookup failure) is propagated immediately and never retried; only a
/// [`SessionOpError::SessionInvalid`] triggers a single re-open-and-retry. If the
/// re-open itself fails, that error is surfaced (no in-process fallback, no
/// fabricated signature).
struct AmortizedSession<S> {
    /// The cached logged-in session, lazily opened on first use and re-opened on a
    /// transient session fault. `None` until the first successful login.
    cached: Mutex<Option<S>>,
}

impl<S> AmortizedSession<S> {
    /// Start with no cached session; the first [`Self::with_session`] call opens
    /// and logs one in.
    fn new() -> Self {
        AmortizedSession {
            cached: Mutex::new(None),
        }
    }

    /// Run `op` against a logged-in session, reusing the cached one when possible.
    ///
    /// 1. Ensure a cached session exists (open + login once if absent).
    /// 2. Run `op` on it. On success, return — NO new login.
    /// 3. On [`SessionOpError::SessionInvalid`], drop the dead session, open a
    ///    fresh logged-in one, and run `op` ONE more time. A second transient
    ///    failure (or a re-open failure) is surfaced — no unbounded retry loop.
    /// 4. On [`SessionOpError::Fatal`], propagate immediately (fail closed).
    fn with_session<F, T, Op>(&self, factory: &F, op: Op) -> Result<T, KeyError>
    where
        F: LoginSessionFactory<Session = S>,
        Op: Fn(&S) -> Result<T, SessionOpError>,
    {
        let mut guard = self
            .cached
            .lock()
            .map_err(|e| KeyError::NotFound(format!("pkcs11: session mutex poisoned: {e}")))?;

        // Ensure a session is cached (first use, or after a prior invalidation
        // cleared it).
        if guard.is_none() {
            *guard = Some(factory.open_logged_in()?);
        }

        // First attempt on the (reused) cached session.
        let first = {
            let session = guard
                .as_ref()
                .ok_or_else(|| KeyError::NotFound("pkcs11: session cache empty".to_string()))?;
            op(session)
        };
        match first {
            Ok(value) => Ok(value),
            Err(SessionOpError::Fatal(e)) => Err(e),
            Err(SessionOpError::SessionInvalid(_)) => {
                // Transient: the cached session is dead. Drop it, open exactly ONE
                // fresh logged-in session, and retry the op once. Re-open failure
                // (or a second transient failure) fails closed.
                *guard = None;
                let session = factory.open_logged_in()?;
                // Cache the fresh session ONLY if the retried op SUCCEEDS (issue
                // #25). A session whose op returned Fatal or SessionInvalid must
                // NOT be cached — leaving the cache empty so the next call re-opens
                // a clean session — otherwise a dead/invalid handle would be reused
                // and every subsequent op would fail until eviction.
                match op(&session) {
                    Ok(value) => {
                        *guard = Some(session);
                        Ok(value)
                    }
                    Err(SessionOpError::Fatal(e)) | Err(SessionOpError::SessionInvalid(e)) => {
                        // `guard` stays None; `session` is dropped (closed) here.
                        Err(e)
                    }
                }
            }
        }
    }
}

/// A cached, logged-in PKCS#11 session reduced to its raw `CK_SESSION_HANDLE`.
///
/// This is the lifetime-free `S` that [`AmortizedSession`] caches for the real
/// source. The wrapper's [`crate::pkcs11_native::Session`] carries a phantom
/// lifetime tying it to its [`Pkcs11Context`], which makes it impossible to store
/// alongside that same context in one struct (self-referential). Because a session
/// is really just a `Copy` handle, we amortize on the HANDLE: open+login once,
/// keep the handle here, and run each op through a non-owning
/// [`SessionRef`](crate::pkcs11_native::SessionRef) against the live context.
///
/// The handle is closed explicitly when this holder is retired (on a transient
/// invalidation, via [`Pkcs11Context::close_session`]); `C_Finalize` on context
/// drop is the backstop for the one currently-cached handle.
struct LoggedInSession {
    /// The raw open+logged-in session handle (owned: closed on retirement).
    handle: CK_SESSION_HANDLE,
    /// Lifetime-free closer for `handle`'s parent context; closes the handle on
    /// drop (retirement by [`AmortizedSession`], or when the source is dropped).
    closer: SessionCloser,
}

impl Drop for LoggedInSession {
    fn drop(&mut self) {
        // Retire the cached handle. A close error on teardown has nowhere
        // meaningful to go (and `C_Finalize` on the context is the backstop), so it
        // is intentionally ignored — but we never call a null pointer (the closer
        // guards that) and we never leak silently while the context lives.
        let _ = self.closer.close(self.handle);
    }
}

/// Classify a wrapper [`Pkcs11Error`]: `true` when re-opening a fresh logged-in
/// session could plausibly cure it (the current session handle is invalid/closed,
/// the login lapsed, or the device had a transient fault). A `false` here means the
/// error is intrinsic to the operation (bad mechanism, malformed object, …) and a
/// reconnect would not help — fail closed (a real sign/lookup error is NOT retried).
fn is_session_invalid(error: &Pkcs11Error) -> bool {
    match error {
        Pkcs11Error::Ck { rv, .. } => matches!(
            *rv,
            CKR_SESSION_HANDLE_INVALID
                | CKR_SESSION_CLOSED
                | CKR_SESSION_COUNT
                | CKR_USER_NOT_LOGGED_IN
                | CKR_DEVICE_ERROR
                | CKR_DEVICE_REMOVED
        ),
        // Load / missing-function / protocol shape errors are not transient session
        // faults — re-opening would not cure them. Fail closed.
        Pkcs11Error::Load(_)
        | Pkcs11Error::MissingFunction(_)
        | Pkcs11Error::Protocol(_) => false,
    }
}

/// Map a wrapper [`Pkcs11Error`] from a token op into a [`SessionOpError`]: a
/// session-fault CK_RV becomes [`SessionOpError::SessionInvalid`] (retry once),
/// everything else [`SessionOpError::Fatal`] (propagate, fail closed). `make_fatal`
/// builds the contextual [`KeyError`] for the fatal/propagated case (matching the
/// pre-amortization error text exactly).
fn classify_op_error(
    error: Pkcs11Error,
    make_fatal: impl FnOnce(&Pkcs11Error) -> KeyError,
) -> SessionOpError {
    if is_session_invalid(&error) {
        // Retryable: surface a NotFound carrying the transient cause; the retry
        // path discards the message, so the text is diagnostic only.
        SessionOpError::SessionInvalid(KeyError::NotFound(format!(
            "pkcs11: transient session fault: {error}"
        )))
    } else {
        SessionOpError::Fatal(make_fatal(&error))
    }
}

/// A PKCS#11-backed [`KeySource`] whose Ed25519 response-signing key lives on a
/// hardware/software token and is exercised only via `C_Sign` — the private key
/// never leaves the device. TLS material is delegated to an inner
/// [`FileKeySource`] (see the module doc for the delegated-TLS-signing follow-up).
///
/// The PIN is held in [`Zeroizing`] so it is scrubbed from memory on drop.
///
/// A single logged-in session is AMORTIZED across operations (audit M16): rather
/// than a `C_Login` per signed response — which makes signing latency/availability
/// hostage to the token's login throughput, a boundary DoS amplification — the
/// source keeps one logged-in session in [`AmortizedSession`] and reuses it,
/// re-logging in only when that session goes invalid. The authenticated window is
/// the proxy's lifetime, which is the intended posture for a sidecar that signs
/// every response; fail-closed behaviour on genuine login/sign errors is preserved.
pub struct Pkcs11KeySource {
    // FIELD ORDER IS LOAD-BEARING. Rust drops struct fields in declaration order,
    // so `session` MUST precede `context`: the cached [`LoggedInSession`] closes
    // its handle (`C_CloseSession`, via its [`SessionCloser`]) on drop, and that
    // call dereferences `context`'s function list — which `Pkcs11Context::drop`
    // FINALIZES (`C_Finalize`). Dropping `context` first would make the session's
    // closer call into a finalized module (use-after-finalize → crash). With
    // `session` first, every cached handle is closed BEFORE `C_Finalize` runs.
    /// One logged-in session (cached by raw handle) reused across signs /
    /// public-key reads (M16): a fresh login happens only on first use or after a
    /// transient session invalidation. Declared first so it drops before `context`.
    session: AmortizedSession<LoggedInSession>,
    /// The loaded Cryptoki context (owns the module handle; finalized on drop).
    /// Declared after `session` so `C_Finalize` runs only after the cached session
    /// handle has been closed (see the field-order note above).
    context: Pkcs11Context,
    /// The id of the slot whose token holds the signing key.
    slot: CK_SLOT_ID,
    /// The token User PIN, scrubbed on drop.
    pin: Zeroizing<String>,
    /// The CKA_LABEL of the Ed25519 PRIVATE key object (used via `C_Sign` only).
    key_label: String,
    /// File-backed source for the TLS cert chain / TLS key / client-CA roots.
    tls: FileKeySource,
}

impl Pkcs11KeySource {
    /// Open a PKCS#11 token and bind to the named Ed25519 signing key.
    ///
    /// Loads the Cryptoki module at `module_path`, initializes it, selects the
    /// token whose label equals `token_label`, opens a logged-in User session to
    /// confirm the PIN and locate the Ed25519 PRIVATE and PUBLIC key objects by
    /// `key_label`, then closes that probe session (each later operation opens its
    /// own). The TLS cert chain, TLS key, and client-CA roots are loaded from the
    /// given file paths via an inner [`FileKeySource`].
    ///
    /// Every failure maps to a [`KeyError`] with context (fail closed); this never
    /// panics and never substitutes an in-process key.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        module_path: &str,
        pin: &str,
        token_label: &str,
        key_label: &str,
        tls_cert_path: &str,
        tls_key_path: &str,
        client_ca_path: &str,
    ) -> Result<Self, KeyError> {
        // Load the module and C_Initialize with OS locking (CKF_OS_LOCKING_OK)
        // through the owned safe wrapper over the raw cryptoki-sys FFI bindings.
        let context = Pkcs11Context::load_and_initialize(module_path).map_err(|e| {
            KeyError::NotFound(format!("pkcs11: load+initialize module '{module_path}': {e}"))
        })?;

        let slot = find_token_slot(&context, token_label)?;
        let pin = Zeroizing::new(pin.to_string());

        let source = Pkcs11KeySource {
            context,
            slot,
            pin,
            key_label: key_label.to_string(),
            tls: FileKeySource {
                // The token custodies the response-signing key, so this inner
                // file source's signing-key path is never read; give it the TLS
                // key path as an inert, valid placeholder rather than an empty
                // string. Only the TLS accessors below are ever delegated to it.
                signing_key_seed_path: tls_key_path.to_string(),
                tls_cert_path: tls_cert_path.to_string(),
                tls_key_path: tls_key_path.to_string(),
                client_ca_path: client_ca_path.to_string(),
            },
            session: AmortizedSession::new(),
        };

        // Prove, at construction, that the PIN logs in and BOTH key objects exist
        // — so a misconfiguration fails closed at startup rather than on the first
        // signed response. This runs through the amortized session, so it ALSO
        // primes the cache: the one login here is the login every later op reuses.
        source.session.with_session(&source, |logged_in| {
            let view = source.context.with_handle(logged_in.handle);
            find_key(&view, &source.key_label, ObjectClass::Private)?;
            find_key(&view, &source.key_label, ObjectClass::Public)?;
            Ok::<(), SessionOpError>(())
        })?;

        Ok(source)
    }
}

/// The real source opens ONE logged-in session per [`open_logged_in`] call —
/// exactly the login that [`AmortizedSession`] makes rare. The returned
/// [`LoggedInSession`] owns its raw handle and closes it on retirement.
impl LoginSessionFactory for Pkcs11KeySource {
    type Session = LoggedInSession;

    fn open_logged_in(&self) -> Result<LoggedInSession, KeyError> {
        let handle = self
            .context
            .open_logged_in_handle(self.slot, &self.pin)
            .map_err(|e| KeyError::NotFound(format!("pkcs11: open+login session: {e}")))?;
        Ok(LoggedInSession {
            handle,
            closer: self.context.session_closer(),
        })
    }
}

/// Locate the single Ed25519 key object of the given class with `key_label`
/// against an open session view, classified for the amortization layer.
///
/// A transient session fault during the find is [`SessionOpError::SessionInvalid`]
/// (retry once); any other wrapper error is [`SessionOpError::Fatal`] with the SAME
/// `NotFound` context text as the pre-amortization path. The count cases are
/// intrinsic, never a session fault: zero matches is a [`KeyError::NotFound`] Fatal;
/// more than one is a [`KeyError::Malformed`] Fatal (an ambiguous token config must
/// fail closed, never silently pick one). A re-open would not change these.
fn find_key(
    view: &SessionRef<'_>,
    key_label: &str,
    class: ObjectClass,
) -> Result<CK_OBJECT_HANDLE, SessionOpError> {
    let template = AttributeTemplate::ed25519_labelled(class, key_label);
    let mut handles = view.find_objects(&template).map_err(|e| {
        classify_op_error(e, |e| {
            KeyError::NotFound(format!("pkcs11: find key '{key_label}': {e}"))
        })
    })?;
    match handles.len() {
        0 => Err(SessionOpError::Fatal(KeyError::NotFound(format!(
            "pkcs11: no Ed25519 key object labelled '{key_label}' (class {})",
            class_name(class)
        )))),
        1 => Ok(handles.remove(0)),
        n => Err(SessionOpError::Fatal(KeyError::Malformed(format!(
            "pkcs11: {n} Ed25519 key objects labelled '{key_label}' (class {}); refusing to guess",
            class_name(class)
        )))),
    }
}

/// Human-readable name for an [`ObjectClass`] in error context (the wrapper enum
/// is intentionally minimal and not `Debug`-printed onto the token path).
fn class_name(class: ObjectClass) -> &'static str {
    match class {
        ObjectClass::Private => "CKO_PRIVATE_KEY",
        ObjectClass::Public => "CKO_PUBLIC_KEY",
    }
}

/// Select the slot whose token's label equals `token_label`. Token labels are
/// stable across reboots (slot ids are not), so this is the primary selector. No
/// match is [`KeyError::NotFound`].
fn find_token_slot(context: &Pkcs11Context, token_label: &str) -> Result<CK_SLOT_ID, KeyError> {
    // `token_slots` enumerates present-token slots and reads each token's label
    // with the 32-byte 0x20 padding already trimmed.
    let slots = context
        .token_slots()
        .map_err(|e| KeyError::NotFound(format!("pkcs11: enumerate token slots: {e}")))?;
    for (slot, label) in slots {
        if label.trim_end() == token_label {
            return Ok(slot);
        }
    }
    Err(KeyError::NotFound(format!(
        "pkcs11: no token with label '{token_label}'"
    )))
}

/// Strip a DER `OCTET STRING` wrapper (`0x04 <len> <bytes>`) if present, returning
/// the raw 32-byte Ed25519 point. PKCS#11 v3 returns `CKA_EC_POINT` as a DER
/// `OCTET STRING` around the curve point; some modules return the bare 32 bytes.
/// Accept both, but reject anything that is not ultimately exactly 32 bytes (fail
/// closed — a wrong-length point cannot be a valid Ed25519 key).
fn raw_ed25519_point(ec_point: &[u8]) -> Result<[u8; ED25519_PUBLIC_KEY_LEN], KeyError> {
    let raw: &[u8] = if ec_point.len() == ED25519_PUBLIC_KEY_LEN {
        ec_point
    } else if ec_point.len() == ED25519_PUBLIC_KEY_LEN + 2
        && ec_point[0] == 0x04
        && usize::from(ec_point[1]) == ED25519_PUBLIC_KEY_LEN
    {
        // DER OCTET STRING: tag 0x04, length 0x20, then the 32-byte point.
        &ec_point[2..]
    } else {
        return Err(KeyError::Malformed(format!(
            "pkcs11: CKA_EC_POINT is {} bytes; expected a raw or OCTET-STRING-wrapped \
             32-byte Ed25519 point",
            ec_point.len()
        )));
    };
    let mut bytes = [0u8; ED25519_PUBLIC_KEY_LEN];
    bytes.copy_from_slice(raw);
    Ok(bytes)
}

/// Signs over the token (`C_Sign` with `CKM_EDDSA`) — the private key never
/// leaves the device — and reads the exportable public point for verification.
impl ResponseSigner for Pkcs11KeySource {
    fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError> {
        // Run the find+sign through the AMORTIZED logged-in session (M16): the
        // login is reused; only a transient session fault triggers ONE re-login.
        self.session.with_session(self, |logged_in| {
            let view = self.context.with_handle(logged_in.handle);
            let private = find_key(&view, &self.key_label, ObjectClass::Private)?;
            // CKM_EDDSA over the raw preimage (NO pre-hash), matching MCP-S's
            // direct Ed25519 signing rule. The token returns the raw 64-byte sig.
            let signature = view.sign_eddsa(private, preimage).map_err(|e| {
                classify_op_error(e, |e| {
                    KeyError::Malformed(format!("pkcs11: C_Sign (CKM_EDDSA): {e}"))
                })
            })?;
            if signature.len() != ED25519_SIGNATURE_LEN {
                // A wrong-length signature is intrinsic (not a session fault) —
                // fail closed, never retry.
                return Err(SessionOpError::Fatal(KeyError::Malformed(format!(
                    "pkcs11: token returned a {}-byte signature; expected {ED25519_SIGNATURE_LEN}",
                    signature.len()
                ))));
            }
            // Match SigningKey::sign EXACTLY: Base64URL-no-pad of the raw 64 bytes.
            Ok(b64url_encode(&signature))
        })
    }

    fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
        self.session.with_session(self, |logged_in| {
            let view = self.context.with_handle(logged_in.handle);
            let public = find_key(&view, &self.key_label, ObjectClass::Public)?;
            let ec_point = view.get_ec_point(public).map_err(|e| {
                classify_op_error(e, |e| {
                    KeyError::Malformed(format!("pkcs11: read CKA_EC_POINT: {e}"))
                })
            })?;
            let bytes = raw_ed25519_point(&ec_point).map_err(SessionOpError::Fatal)?;
            // A non-canonical / off-curve point is a trust-binding failure in
            // mcps-core; surface it as malformed key material here. Intrinsic —
            // not a session fault.
            VerificationKey::from_bytes(&bytes)
                .map_err(|e| {
                    SessionOpError::Fatal(KeyError::Malformed(format!(
                        "pkcs11: invalid Ed25519 public key: {e}"
                    )))
                })
        })
    }
}

/// TLS material is delegated to the inner [`FileKeySource`] (see the module doc:
/// delegated TLS signing through the token is the remaining #4034 sub-item).
impl KeySource for Pkcs11KeySource {
    fn tls_server_cert_chain(&self) -> Result<Vec<CertificateDer<'static>>, KeyError> {
        self.tls.tls_server_cert_chain()
    }
    fn tls_server_key(&self) -> Result<PrivateKeyDer<'static>, KeyError> {
        self.tls.tls_server_key()
    }
    fn client_ca_roots(&self) -> Result<Vec<CertificateDer<'static>>, KeyError> {
        self.tls.client_ca_roots()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::AmortizedSession;
    use super::KeyError;
    use super::LoginSessionFactory;
    use super::SessionOpError;

    /// A fake logged-in session standing in for a Cryptoki `Session` — carries the
    /// login generation that produced it so a test can prove the SAME session
    /// (same generation) is reused across operations.
    struct FakeSession {
        generation: u32,
    }

    /// A counting [`LoginSessionFactory`] fake: every `open_logged_in` is one
    /// "login" (incrementing `logins`), modelling the per-operation `C_Login` the
    /// M16 amortization must eliminate. No SoftHSM, no PKCS#11 — runs everywhere.
    struct CountingFactory {
        /// Total logins performed (each `open_logged_in` call).
        logins: Cell<u32>,
        /// If true, the NEXT `open_logged_in` fails (models a token whose re-login
        /// fails — the amortized layer must surface this, fail closed).
        fail_next_open: Cell<bool>,
    }

    impl CountingFactory {
        fn new() -> Self {
            CountingFactory {
                logins: Cell::new(0),
                fail_next_open: Cell::new(false),
            }
        }
    }

    impl LoginSessionFactory for CountingFactory {
        type Session = FakeSession;

        fn open_logged_in(&self) -> Result<FakeSession, KeyError> {
            if self.fail_next_open.replace(false) {
                return Err(KeyError::NotFound("fake: re-login failed".to_string()));
            }
            let generation = self.logins.get() + 1;
            self.logins.set(generation);
            Ok(FakeSession { generation })
        }
    }

    /// M16 — the load-bearing proof, runs EVERYWHERE (no SoftHSM): driving the sign
    /// path N times through the amortized session performs FAR FEWER than N logins.
    /// With the per-operation-login bug this would be N logins; with amortization it
    /// is exactly one (first use), and every op observes the SAME reused session.
    ///
    /// RED without the fix: a `with_session` that called `open_logged_in` on every
    /// invocation (the old `login_session()`-per-op shape) makes `logins == N`,
    /// failing the `< N` assertion below.
    #[test]
    fn sequential_signs_amortize_to_one_login() {
        let factory = CountingFactory::new();
        let amortized: AmortizedSession<FakeSession> = AmortizedSession::new();

        const N: u32 = 50;
        let mut generations = Vec::new();
        for _ in 0..N {
            let gen = amortized
                .with_session(&factory, |session| Ok::<u32, SessionOpError>(session.generation))
                .expect("amortized op succeeds");
            generations.push(gen);
        }

        assert_eq!(
            factory.logins.get(),
            1,
            "N sequential ops must perform exactly ONE login (amortized), not N"
        );
        assert!(
            factory.logins.get() < N,
            "logins ({}) must be far fewer than the {N} operations",
            factory.logins.get()
        );
        // Every op observed the SAME session generation — proof of reuse, not a
        // fresh per-op session.
        assert!(
            generations.iter().all(|g| *g == 1),
            "every operation must reuse the SAME logged-in session, got {generations:?}"
        );
    }

    /// M16 fail-closed preservation: a FATAL op error is propagated IMMEDIATELY and
    /// NEVER triggers a re-login/retry — a genuine sign failure must not be masked
    /// by the amortization loop.
    #[test]
    fn fatal_error_is_not_retried() {
        let factory = CountingFactory::new();
        let amortized: AmortizedSession<FakeSession> = AmortizedSession::new();

        let result: Result<(), KeyError> = amortized.with_session(&factory, |_session| {
            Err(SessionOpError::Fatal(KeyError::Malformed(
                "fatal sign failure".to_string(),
            )))
        });

        assert!(matches!(result, Err(KeyError::Malformed(_))));
        assert_eq!(
            factory.logins.get(),
            1,
            "a Fatal error must NOT trigger a re-login (no retry); exactly the one \
             initial login occurred"
        );
    }

    /// M16 transient recovery: a SessionInvalid error on the cached session triggers
    /// exactly ONE re-open-and-retry; the retried op runs on a FRESH session
    /// (next generation) and succeeds. Two logins total: the initial one and the
    /// one re-login — bounded, no loop.
    #[test]
    fn session_invalid_reopens_once_and_retries() {
        let factory = CountingFactory::new();
        let amortized: AmortizedSession<FakeSession> = AmortizedSession::new();
        let attempt = Cell::new(0u32);

        let gen = amortized
            .with_session(&factory, |session| {
                let n = attempt.replace(attempt.get() + 1);
                if n == 0 {
                    // First attempt on the cached gen-1 session: simulate the
                    // handle having gone invalid.
                    Err(SessionOpError::SessionInvalid(KeyError::NotFound(
                        "fake: session handle invalid".to_string(),
                    )))
                } else {
                    // Retry, now on the re-opened gen-2 session.
                    Ok::<u32, SessionOpError>(session.generation)
                }
            })
            .expect("retry on the re-opened session succeeds");

        assert_eq!(attempt.get(), 2, "op must run exactly twice (try + one retry)");
        assert_eq!(gen, 2, "the retry must run on the FRESH (re-opened) session");
        assert_eq!(
            factory.logins.get(),
            2,
            "exactly two logins: the initial one and the single re-login"
        );
    }

    /// M16 fail-closed on re-open failure: if the cached session is invalid AND the
    /// re-login itself fails, the original re-open error is surfaced — no infinite
    /// retry, no in-process fallback.
    #[test]
    fn reopen_failure_after_invalid_fails_closed() {
        let factory = CountingFactory::new();
        let amortized: AmortizedSession<FakeSession> = AmortizedSession::new();
        // Prime a cached session (one login), then arm the next open to fail.
        amortized
            .with_session(&factory, |_s| Ok::<(), SessionOpError>(()))
            .expect("prime");
        factory.fail_next_open.set(true);

        let result: Result<(), KeyError> = amortized.with_session(&factory, |_session| {
            Err(SessionOpError::SessionInvalid(KeyError::NotFound(
                "fake: session handle invalid".to_string(),
            )))
        });

        assert!(
            matches!(result, Err(KeyError::NotFound(_))),
            "a failed re-open after invalidation must surface the re-open error"
        );
    }

    /// Issue #25: if the single re-open-and-retry ALSO fails (here, Fatal), the
    /// freshly-opened session must NOT be cached — a session whose op failed must
    /// never be reused. The proof: a SUBSEQUENT op must re-open (a fresh login and
    /// generation), which it can only do if the failed-retry session was dropped
    /// rather than cached.
    #[test]
    fn failed_retry_does_not_cache_the_session() {
        let factory = CountingFactory::new();
        let amortized: AmortizedSession<FakeSession> = AmortizedSession::new();

        // Op A: open gen-1; first attempt SessionInvalid → re-open gen-2; the retry
        // returns Fatal. Two logins so far. gen-2 must NOT be cached.
        let attempt = Cell::new(0u32);
        let result: Result<(), KeyError> = amortized.with_session(&factory, |_s| {
            let n = attempt.replace(attempt.get() + 1);
            if n == 0 {
                Err(SessionOpError::SessionInvalid(KeyError::NotFound(
                    "fake: session handle invalid".to_string(),
                )))
            } else {
                Err(SessionOpError::Fatal(KeyError::Malformed(
                    "fake: retry also fails".to_string(),
                )))
            }
        });
        assert!(matches!(result, Err(KeyError::Malformed(_))));
        assert_eq!(factory.logins.get(), 2, "initial open + one re-open");

        // Op B: because the failed-retry session was NOT cached, the cache is empty
        // and this op must open a THIRD session — proving no dead handle was reused.
        let gen = amortized
            .with_session(&factory, |s| Ok::<u32, SessionOpError>(s.generation))
            .expect("subsequent op succeeds on a freshly opened session");
        assert_eq!(
            factory.logins.get(),
            3,
            "the failed-retry session must not be cached; the next op must re-open"
        );
        assert_eq!(
            gen, 3,
            "the next op must run on a freshly opened session, not the failed one"
        );
    }
}
