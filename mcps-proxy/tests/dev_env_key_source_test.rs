//! MCPS-076 (audit gap G-3) — dev-only `EnvKeySource` + secret-hygiene proofs.
//!
//! This target is built ONLY with the non-default `dev_env_key_source` cargo
//! feature (it is `manual`-tagged in BUILD.bazel; a default `bazel test //...`
//! skips it). It proves the dev-only behaviors that cannot even compile in a
//! production build:
//!
//!   * `EnvKeySource` reads the seed WITHOUT mutating the process environment
//!     (issue #25: `std::env::remove_var` is unsound under threads; child-process
//!     secret isolation is handled by the inner-launch env policy, not global
//!     removal), and the loaded key signs correctly;
//!   * a `KeyError` from a malformed seed never carries the secret bytes;
//!   * dropping a `zeroize::Zeroizing<T>` invokes `Zeroize::zeroize` on its
//!     payload, and `zeroize()` zeros the bytes in place — both machine-verified
//!     (see `zeroize_on_drop_invokes_zeroize`).

#![cfg(feature = "dev_env_key_source")]

use mcps_core::b64url_encode;
use mcps_core::SigningKey;
use mcps_proxy::key_source::EnvKeySource;
use mcps_proxy::key_source::KeyError;
use mcps_proxy::key_source::KeySource;

const SEED: [u8; 32] = [7u8; 32];

fn expected_pubkey() -> String {
    SigningKey::from_seed_bytes(&SEED).public_key().to_b64url()
}

/// EFFECT test: the dev-only env source loads the seed and the loaded key signs
/// (its public key matches the seed's), WITHOUT mutating the process environment
/// (issue #25). The previous behavior removed the var via the unsound
/// `std::env::remove_var`; the read is now a pure read — the seed var REMAINS set,
/// and child-process secret isolation is the inner-launch env policy's job (no env
/// inheritance by default), not a global mutation here.
#[test]
fn env_source_signs_without_mutating_process_env() {
    let seed_v = "MCPS076_SEED_AFTER_READ";
    let seed_b64 = b64url_encode(&SEED);
    std::env::set_var(seed_v, &seed_b64);
    assert!(std::env::var(seed_v).is_ok(), "precondition: var is set");

    let source = EnvKeySource {
        signing_key_seed_var: seed_v.to_string(),
        tls_cert_var: "MCPS076_UNUSED_CERT".to_string(),
        tls_key_var: "MCPS076_UNUSED_KEY".to_string(),
        client_ca_var: "MCPS076_UNUSED_CA".to_string(),
    };

    let key = source.signing_key().expect("loads the seed");
    // The loaded key actually signs (its public key matches the seed's).
    assert_eq!(key.public_key().to_b64url(), expected_pubkey());

    // The read does NOT mutate the process environment: the var is still present
    // (no unsound global `remove_var`).
    assert!(
        std::env::var(seed_v).is_ok(),
        "EnvKeySource::read must not mutate the process environment"
    );
    std::env::remove_var(seed_v); // test teardown only
}

/// The error from a malformed env-supplied seed must not contain the secret bytes
/// (Display or Debug) — errors are logged, secrets must not be.
#[test]
fn env_key_error_does_not_leak_seed() {
    let seed_v = "MCPS076_LEAK_SEED";
    let secret = "SUPER_SECRET_BUT_NOT_BASE64_!!!";
    std::env::set_var(seed_v, secret);
    let source = EnvKeySource {
        signing_key_seed_var: seed_v.to_string(),
        tls_cert_var: "x".to_string(),
        tls_key_var: "x".to_string(),
        client_ca_var: "x".to_string(),
    };
    let err = source.signing_key().expect_err("malformed seed must error");
    assert!(matches!(err, KeyError::Malformed(_)));
    let rendered = format!("{err} | {err:?}");
    assert!(
        !rendered.contains(secret),
        "KeyError must not contain the secret seed value; got: {rendered}"
    );
    std::env::remove_var(seed_v);
}

/// MACHINE-VERIFIED zeroize-on-drop, the SOUND (non-UB) variant.
///
/// HONESTY NOTE on what is verified vs. trusted:
///   * I FIRST tried the raw-pointer "read just-freed heap" idiom; in a debug
///     build it FAILED (the freed buffer was not observably all-zero), confirming
///     that idiom is allocator-dependent / UB-fragile. Rather than be dishonest, I
///     replaced it with the assertion below, which is DETERMINISTIC and sound.
///   * What is MACHINE-VERIFIED here, both through LIVE references (no freed
///     memory is read): (a) calling `zeroize()` on a live spy zeros its bytes in
///     place; and (b) dropping a `Zeroizing<T>` invokes `Zeroize::zeroize` on its
///     payload (the spy's `zeroize()` records into an `AtomicBool` that is observed
///     set after the drop). Together these prove WE wired `Zeroizing` so that drop
///     scrubs the value.
///   * What is TRUSTED-TO-CRATE: that `zeroize` actually overwrites real seed
///     bytes with a volatile, un-elidable write (the `zeroize` crate's core
///     guarantee). We assert we invoked it; we do not re-verify the crate's
///     internal volatile-write correctness.
///
/// The companion `seed_temporaries_are_zeroizing_typed` test confirms, at compile
/// time, that a `Zeroizing<[u8;32]>` deref-coerces into `SigningKey::from_seed_bytes`
/// — the exact wrapper-to-constructor pattern `key_source` uses. That `key_source`
/// actually wraps its seed temporaries in `Zeroizing` is a structural property of
/// the source (verified by reading it / review), not something a runtime test can
/// observe, since zeroize is invisible at the value level.
#[test]
fn zeroize_on_drop_invokes_zeroize() {
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use zeroize::Zeroize;
    use zeroize::Zeroizing;

    static ZEROIZED: AtomicBool = AtomicBool::new(false);

    /// A spy payload: `zeroize()` records that it ran and clears its own bytes.
    struct Spy {
        bytes: [u8; 32],
    }
    impl Zeroize for Spy {
        fn zeroize(&mut self) {
            self.bytes.zeroize();
            ZEROIZED.store(true, Ordering::SeqCst);
        }
    }

    // (a) Calling zeroize() on a LIVE spy zeros its bytes in place — observed
    // through a live reference (the value is NOT dropped/freed here).
    ZEROIZED.store(false, Ordering::SeqCst);
    let mut live = Spy { bytes: [0xA5; 32] };
    assert_eq!(live.bytes, [0xA5; 32], "sentinel set before zeroize");
    live.zeroize();
    assert_eq!(live.bytes, [0u8; 32], "zeroize() must zero the bytes in place");
    assert!(ZEROIZED.load(Ordering::SeqCst), "zeroize() must have run");

    // (b) Dropping a Zeroizing<T> invokes Zeroize::zeroize on its payload.
    ZEROIZED.store(false, Ordering::SeqCst);
    {
        let spy: Zeroizing<Spy> = Zeroizing::new(Spy { bytes: [0xA5; 32] });
        // Sanity through a LIVE reference (no freed memory): the sentinel is set.
        assert_eq!(spy.bytes, [0xA5; 32]);
        // (spy drops here)
    }
    assert!(
        ZEROIZED.load(Ordering::SeqCst),
        "dropping Zeroizing<T> did not invoke Zeroize::zeroize on its payload"
    );
}

/// COMPILE-LEVEL demonstration of the wrapper-to-constructor contract `key_source`
/// relies on: a `zeroize::Zeroizing<[u8;32]>` deref-coerces into
/// `SigningKey::from_seed_bytes(&[u8;32])` and yields the same key as the raw seed.
///
/// This does NOT (and cannot at runtime) verify that `key_source` wraps its seed
/// temporaries in `Zeroizing` — zeroize is invisible at the value level, and
/// `signing_key_from_seed_b64url` is private. That wrapping is a structural
/// property of the source. What this pins is that the `Zeroizing` wrapper is a
/// drop-in for the raw `&[u8;32]` the dalek constructor borrows, so the production
/// code can wrap without changing behavior. Scrub-on-drop itself is proven by
/// `zeroize_on_drop_invokes_zeroize`.
#[test]
fn seed_temporaries_are_zeroizing_typed() {
    let seed: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new([7u8; 32]);
    // Deref-coerces to &[u8;32] exactly as `SigningKey::from_seed_bytes` requires,
    // and produces the same key as the unwrapped seed would.
    let key = SigningKey::from_seed_bytes(&seed);
    assert_eq!(key.public_key().to_b64url(), expected_pubkey());
}
