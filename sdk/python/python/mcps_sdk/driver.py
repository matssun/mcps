"""MCP-S conformance driver — the Python SDK as an interchangeable client leg.

This is the Python side of the multi-SDK test architecture (see
``mcps-walkthrough`` `ClientDriver`). It is a thin stdio bridge that makes the
Python SDK a drop-in for the Rust reference ``mcps-client-proxy-cli``: it reads one
plain MCP JSON-RPC request per line on stdin, signs it with the SDK, POSTs it over
mTLS to the ``mcps-proxy`` PEP, verifies the server-signed response, strips the
MCP-S envelope, and writes one plain MCP JSON-RPC response per line on stdout.

The signing/verification is the AUDITED ``mcps-client-core`` logic via the SDK's
PyO3 core (``sign_request_with_signer`` / ``verify_response``) — the exact calls the
live mTLS interop test (``tests/test_e2e_mtls.py``) proves against the real proxy.
No ``mcp`` dependency: the harness IS the MCP client, so this bridge never opens a
``ClientSession``; it only signs the raw JSON-RPC it is handed.

Run it as the walkthrough harness's Python client leg::

    MCPS_DRIVER_PYTHON="python3 -m mcps_sdk.driver" \\
      cargo test -p mcps-walkthrough --test sdk_driver_matrix -- --nocapture

The harness appends the shared client CLI arg surface (``--remote-addr`` … ). Only
the file/software key source is supported here (the four-hop's offline tiers);
Cloud KMS signing on the Python side is a later slice.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import socket
import ssl
import sys
import time
import urllib.request
from datetime import datetime, timezone

import mcps_sdk

# A concrete, valid authorization-binding digest (SHA-256 of the empty artifact,
# Base64URL-no-pad) — the same value the live mTLS interop test signs with. The
# four-hop PEP verifies the request signature over the preimage (which includes the
# binding) but enforces no authorization scope, so any self-consistent binding is
# accepted; this one is proven against the real proxy.
_AUTHZ_DIGEST = "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"

# JSON-RPC server-error code carrying a fail-closed MCP-S rejection back to the
# harness (matches the SDK's McpsHttpTransport reject code).
_MCPS_REJECTED_CODE = -32099


def _rfc3339(unix: int) -> str:
    return datetime.fromtimestamp(unix, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _b64url_decode(value: str) -> bytes:
    """Decode Base64URL, tolerating missing padding (the SDK/CLI wire form)."""
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def _read_seed(spec: str) -> bytes:
    """Resolve ``--signing-key-seed`` (a Base64URL seed, or ``@<path>`` to a file
    holding one) to the raw 32 seed bytes — the CLI's ``@file`` convention."""
    raw = spec
    if spec.startswith("@"):
        with open(spec[1:], "r", encoding="utf-8") as fh:
            raw = fh.read().strip()
    seed = _b64url_decode(raw)
    if len(seed) != 32:
        raise ValueError(f"signing key seed must be 32 bytes, got {len(seed)}")
    return seed


def _canonical_audience(six_field: str) -> str:
    """Reproduce ``mcps_client_core::AudienceTuple::to_audience_string`` from the
    6-field ``--audience`` form (``scheme,host,port,tenant,route,realm``). Mirrors
    ``mcps-client-core/src/audience.rs``; a drift makes the round trip fail closed
    (audience mismatch), never silently pass."""
    parts = six_field.split(",")
    if len(parts) != 6:
        raise ValueError(f"--audience must have 6 comma fields, got {len(parts)}: {six_field!r}")
    scheme, host, port, tenant, route, realm = parts
    return (
        f"mcps-audience:v1:scheme={scheme};host={host};port={port};"
        f"tenant={tenant};route={route};realm={realm}"
    )


def _gcp_access_token(use_metadata: bool) -> str:
    """The OAuth2 bearer for Cloud KMS: the GCE metadata server (``--gcp-kms-use-
    metadata``) or ``MCPS_GCP_ACCESS_TOKEN`` — mirroring the Rust backend's sources."""
    if use_metadata:
        req = urllib.request.Request(
            "http://metadata.google.internal/computeMetadata/v1/instance/"
            "service-accounts/default/token",
            headers={"Metadata-Flavor": "Google"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.load(resp)["access_token"]
    token = os.environ.get("MCPS_GCP_ACCESS_TOKEN", "")
    if not token:
        raise SystemExit(
            "MCPS_GCP_ACCESS_TOKEN must be set for --key-source gcp-kms "
            "(or pass --gcp-kms-use-metadata on a GCE instance)"
        )
    return token


def _gcp_kms_sign_callback(key_version: str, endpoint: str | None, token: str):
    """A non-exporting signer callback: Ed25519-sign the preimage via Cloud KMS
    ``asymmetricSign`` and return the Base64URL-no-pad signature the SDK core wants.

    The KMS key is ``EC_SIGN_ED25519`` (PureEdDSA), so the RAW preimage is signed as
    ``data`` (not a pre-hashed digest) — the SAME preimage and algorithm the software
    path signs, no substitution. The private key never leaves KMS (custody
    ``NonExporting``)."""
    base = endpoint or "https://cloudkms.googleapis.com"
    url = f"{base}/v1/{key_version}:asymmetricSign"

    def sign(preimage: bytes) -> str:
        body = json.dumps({"data": base64.b64encode(preimage).decode()}).encode()
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.load(resp)
        raw_sig = base64.b64decode(payload["signature"])  # 64-byte Ed25519 signature
        return base64.urlsafe_b64encode(raw_sig).decode().rstrip("=")

    return sign


def _build_signer(args: argparse.Namespace):
    """Build the request signer + custody policy for the configured key source: a
    software seed (default) or a non-exporting Cloud KMS key (``--key-source
    gcp-kms``, the SDK's ``Signer.non_exporting`` seam under the hardening profile)."""
    if args.key_source == "gcp-kms":
        if not args.gcp_kms_key_version:
            raise SystemExit("--gcp-kms-key-version is required for --key-source gcp-kms")
        token = _gcp_access_token(args.gcp_kms_use_metadata)
        callback = _gcp_kms_sign_callback(args.gcp_kms_key_version, args.gcp_kms_endpoint, token)
        signer = mcps_sdk.Signer.non_exporting(
            signer_id=args.signer_id, key_id=args.key_id, sign_callback=callback
        )
        policy = mcps_sdk.SignerPolicy(
            args.signer_id, environment="production", require_mcps=True
        ).require_non_exporting()
        return signer, policy
    if not args.signing_key_seed:
        raise SystemExit("--signing-key-seed is required for --key-source file")
    signer = mcps_sdk.Signer.software(
        _read_seed(args.signing_key_seed), signer_id=args.signer_id, key_id=args.key_id
    )
    policy = mcps_sdk.SignerPolicy(args.signer_id, environment="dev-test", require_mcps=True)
    return signer, policy


def _continuation_state(params) -> "str | None":
    """If ``params`` is a continuation answer (carries ``inputResponses`` AND an
    echoed ``requestState``, SEP-2322), return the ``requestState`` handle; else None.
    The handle keys the recorded multi-round-trip binding (ADR-MCPS-047)."""
    if isinstance(params, dict) and "inputResponses" in params and "requestState" in params:
        state = params["requestState"]
        return state if isinstance(state, str) else None
    return None


def _strip_envelope(obj: dict) -> dict:
    """Remove the MCP-S response envelope from ``result._meta`` so the harness sees
    plain MCP (and no ``_meta`` at all when the envelope was its only key)."""
    result = obj.get("result")
    if isinstance(result, dict):
        meta = result.get("_meta")
        if isinstance(meta, dict):
            meta.pop(mcps_sdk.response_meta_key(), None)
            if not meta:
                result.pop("_meta", None)
    return obj


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="mcps_sdk.driver", add_help=False)
    p.add_argument("--remote-addr", required=True)          # host:port
    p.add_argument("--server-name", required=True)          # expected server cert SAN
    p.add_argument("--signer-id", required=True)
    p.add_argument("--key-id", required=True)
    p.add_argument("--signing-key-seed")                    # <b64url> | @<path> (file source)
    p.add_argument("--server-signer", required=True)
    p.add_argument("--server-key-id", required=True)
    p.add_argument("--server-pubkey", required=True)        # raw-32 b64url
    p.add_argument("--audience", required=True)             # 6-field form
    p.add_argument("--tls-cert", required=True)             # client leaf
    p.add_argument("--tls-key", required=True)
    p.add_argument("--server-ca", required=True)
    p.add_argument("--on-behalf-of", required=True)
    # Key source: software seed (default) or non-exporting Cloud KMS.
    p.add_argument("--key-source", default="file")          # file | gcp-kms
    p.add_argument("--gcp-kms-key-version")
    p.add_argument("--gcp-kms-endpoint")
    p.add_argument("--gcp-kms-use-metadata", action="store_true")
    return p.parse_args(argv)


def _make_post(args: argparse.Namespace):
    """One mTLS HTTP/1.1 POST per call (Connection: close) — the proxy's wire."""
    host, port_s = args.remote_addr.rsplit(":", 1)
    port = int(port_s)
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=args.server_ca)
    ctx.load_cert_chain(args.tls_cert, args.tls_key)

    def post(body: bytes) -> bytes:
        raw = socket.create_connection((host, port), timeout=15)
        try:
            tls = ctx.wrap_socket(raw, server_hostname=args.server_name)
        except Exception:
            raw.close()  # don't leak the TCP socket on a handshake/config failure
            raise
        try:
            head = (
                f"POST / HTTP/1.1\r\nHost: {args.server_name}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode()
            tls.sendall(head + body)
            chunks = []
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            tls.close()
        return b"".join(chunks).split(b"\r\n\r\n", 1)[1]

    return post


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    signer, policy = _build_signer(args)
    resolver = mcps_sdk.TrustResolver()
    resolver.insert_public_key(
        args.server_signer, args.server_key_id, _b64url_decode(args.server_pubkey)
    )
    audience = _canonical_audience(args.audience)
    post = _make_post(args)

    out = sys.stdout

    def emit(obj: dict) -> None:
        out.write(json.dumps(obj, separators=(",", ":")))
        out.write("\n")
        out.flush()

    # ADR-MCPS-047 multi-round-trip state: the opaque server ``requestState`` handle ->
    # the verified continuation binding ``(previous_request_hash,
    # input_required_response_hash)``. Populated when an ``InputRequiredResult`` is
    # verified; consumed (single-use) when the client answers it. Persists across the
    # line loop (one long-lived driver process per session).
    mrt: dict = {}

    # readline() (NOT `for line in sys.stdin`): iterating the stream read-aheads and
    # would deadlock this one-request-then-await-response protocol.
    while True:
        raw_line = sys.stdin.readline()
        if not raw_line:  # EOF: the harness closed stdin
            break
        line = raw_line.strip()
        if not line:
            continue
        request = json.loads(line)
        rid = request.get("id")
        method = request.get("method")
        if method is None:
            # Not a request we can sign (notification/response); the four-hop only
            # sends id-bearing requests. Fail closed rather than hang.
            emit(_reject(rid, "mcps.missing_envelope"))
            continue
        params = request.get("params", {})

        # ADR-MCPS-047 answer leg: a call carrying ``inputResponses`` + an echoed
        # ``requestState`` is a continuation. Bind it to the verified
        # ``InputRequiredResult`` recorded under that handle; no recorded state
        # (unknown or already-used) fails closed — we never sign an unbound continuation.
        continuation_kwargs: dict = {}
        request_state = _continuation_state(params)
        if request_state is not None:
            entry = mrt.pop(request_state, None)
            if entry is None:
                emit(_reject(rid, "mcps.continuation_malformed"))
                continue
            continuation_kwargs = {
                "continuation_previous_request_hash": entry[0],
                "continuation_input_required_response_hash": entry[1],
            }

        try:
            now = int(time.time())
            signed = mcps_sdk.sign_request_with_signer(
                json.dumps(rid),
                method,
                json.dumps(params),
                on_behalf_of=args.on_behalf_of,
                audience=audience,
                binding_digest_alg="sha256",
                binding_digest_value=_AUTHZ_DIGEST,
                nonce=secrets.token_urlsafe(16),
                issued_at=_rfc3339(now),
                expires_at=_rfc3339(now + 300),
                signer=signer,
                policy=policy,
                **continuation_kwargs,
            )
            body = post(signed.wire_bytes)
            result = mcps_sdk.verify_response(
                body,
                resolver=resolver,
                expected_request_hash=signed.request_hash,
                expected_server_signer=args.server_signer,
                enforcement_mode="require_mcps",
            )
        except Exception as exc:  # noqa: BLE001 — surface as a fail-closed reject, never hang
            emit(_reject(rid, f"mcps.driver_error: {exc}"))
            continue

        if result.accepted:
            plain = _strip_envelope(json.loads(body))
            # A verified, NON-TERMINAL InputRequiredResult (D7): record the continuation
            # binding keyed by the server's opaque requestState so the answer leg can
            # bind it. The elicitation is delivered to the harness either way.
            if result.input_required:
                inner = plain.get("result")
                state = inner.get("requestState") if isinstance(inner, dict) else None
                if isinstance(state, str):
                    mrt[state] = (signed.request_hash, result.response_hash)
            emit(plain)
        else:
            emit(_reject(rid, result.reason))

    return 0


def _reject(rid, reason) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "error": {"code": _MCPS_REJECTED_CODE, "message": reason or "mcps.verification_failed"},
    }


if __name__ == "__main__":
    raise SystemExit(main())
