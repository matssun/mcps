"""Custody / signer-policy binding tests (issue #199, ADR-MCPS-044 §Key custody).

`sign_request_with_signer` runs `build_signed_request_with_signer`: it authorizes
the signer against the policy BEFORE signing (identity match, revocation, hardening
profile, and the production dev-file rule), then binds the evidence to the signer's
actual identity. These tests assert the gate behaves identically to the Rust core,
and that the signed bytes still match the parity golden vector.
"""

import json
from pathlib import Path

import pytest

import mcps_sdk

FIXTURE = Path(__file__).parent / "fixtures" / "sign_request_vector.json"
INPUTS = json.loads(FIXTURE.read_text())["inputs"]
EXPECTED = json.loads(FIXTURE.read_text())
SEED = bytes.fromhex(INPUTS["seed_hex"])
SIGNER_ID = INPUTS["signer"]
KEY_ID = INPUTS["key_id"]


def _sign_with(signer, policy):
    return mcps_sdk.sign_request_with_signer(
        INPUTS["id_json"],
        INPUTS["method"],
        INPUTS["params_json"],
        on_behalf_of=INPUTS["on_behalf_of"],
        audience=INPUTS["audience"],
        binding_digest_alg=INPUTS["binding_digest_alg"],
        binding_digest_value=INPUTS["binding_digest_value"],
        nonce=INPUTS["nonce"],
        issued_at=INPUTS["issued_at"],
        expires_at=INPUTS["expires_at"],
        signer=signer,
        policy=policy,
    )


def _software_signer():
    return mcps_sdk.Signer.software(SEED, signer_id=SIGNER_ID, key_id=KEY_ID)


def _dev_file_signer():
    return mcps_sdk.Signer.dev_file(SEED, signer_id=SIGNER_ID, key_id=KEY_ID)


def _policy(*, environment="production", require_mcps=True, expected=SIGNER_ID):
    return mcps_sdk.SignerPolicy(
        expected, environment=environment, require_mcps=require_mcps
    )


def test_signer_metadata():
    sw = _software_signer()
    assert sw.signer_id == SIGNER_ID
    assert sw.key_id == KEY_ID
    assert sw.custody == "software-held-private"
    assert _dev_file_signer().custody == "dev-file-unprotected"


def test_signer_path_matches_parity_vector():
    """The custody path produces the SAME bytes/hash as the raw oracle vector —
    build_signed_request_with_signer funnels through the same envelope builder."""
    signed = _sign_with(_software_signer(), _policy())
    assert signed.wire_bytes.decode() == EXPECTED["expected_wire_bytes"]
    assert signed.request_hash == EXPECTED["expected_request_hash"]


def test_software_signer_accepted_under_require_mcps_production():
    """Software-held-private custody is acceptable for the base production posture."""
    signed = _sign_with(_software_signer(), _policy())
    assert signed.request_hash.startswith("sha256:")


def test_dev_file_signer_rejected_under_require_mcps_production():
    """An unprotected dev file key fails closed under production `require_mcps`."""
    with pytest.raises(ValueError, match="ActorBindingFailed"):
        _sign_with(_dev_file_signer(), _policy())


def test_dev_file_signer_accepted_in_dev_test():
    """The same dev file key is permitted in an explicitly-labelled dev/test env."""
    signed = _sign_with(_dev_file_signer(), _policy(environment="dev-test"))
    # identical bytes — the custody class never changes the signed preimage.
    assert signed.wire_bytes.decode() == EXPECTED["expected_wire_bytes"]


def test_signer_identity_mismatch_rejected():
    """A signer that is not the one the policy binds fails closed."""
    with pytest.raises(ValueError, match="ActorBindingFailed"):
        _sign_with(_software_signer(), _policy(expected="did:example:someone-else"))


def test_revoked_key_id_rejected():
    """Signing through a revoked key id fails closed (rotation/revocation)."""
    policy = _policy().revoke_key_id(KEY_ID)
    with pytest.raises(ValueError, match="ActorBindingFailed"):
        _sign_with(_software_signer(), policy)


def test_hardening_profile_rejects_software_key():
    """The non-exporting hardening profile excludes software-held-private custody."""
    policy = _policy().require_non_exporting()
    with pytest.raises(ValueError, match="ActorBindingFailed"):
        _sign_with(_software_signer(), policy)


def test_unknown_environment_rejected():
    with pytest.raises(ValueError, match="environment must be"):
        mcps_sdk.SignerPolicy(SIGNER_ID, environment="staging", require_mcps=True)
