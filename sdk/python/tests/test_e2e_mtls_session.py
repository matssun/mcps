"""Live full-`ClientSession` MCP-S over mTLS — step (ii).

Where step (i) (`test_e2e_mtls.py`) drove ONE raw signed request per mTLS
connection, this runs a REAL `mcp.ClientSession` — `initialize()` then
`call_tool("read_file")` — through :func:`mcps_sdk.connect_mtls_http`, against the
REAL production `mcps-proxy` fronting the REAL `mcps-demo-fileserver`:

    ClientSession.initialize()
      -> McpsHttpTransport signs the `initialize` request
      -> one mTLS POST -> mcps-proxy verifies -> fileserver -> signed InitializeResult
      -> verified + stripped -> ClientSession negotiates the protocol version
    ClientSession sends notifications/initialized
      -> dropped (no fire-and-forget channel; fileserver is stateless)
    ClientSession.call_tool("read_file", ...)
      -> one more signed mTLS POST -> verified file content

The proxy speaks one HTTP/1.1 POST per connection (`Connection: close`), so each
request opens its own mTLS connection — the transport maps ClientSession's stream
model onto that request/response wire. Fail-closed verification surfaces as a
JSON-RPC error correlated to the request id, so the awaiting call RAISES (a
read-stream Exception would instead hang the call — see http_transport.py).

Materials come from `DemoFixtures` via the `emit_mtls_fixtures` example; needs the
built binaries + cargo (skips cleanly otherwise):
    cargo build -p mcps-proxy && cargo build -p mcps-demo-fileserver
"""

import json
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest

import mcps_sdk

anyio = pytest.importorskip("anyio")
pytest.importorskip("mcp")
from mcp.shared.exceptions import McpError  # noqa: E402
from mcp.shared.message import SessionMessage  # noqa: E402
from mcp.types import JSONRPCMessage  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
PROXY = ROOT / "target" / "debug" / "mcps-proxy"
FILESERVER = ROOT / "target" / "debug" / "mcps-demo-fileserver"

if not (PROXY.exists() and FILESERVER.exists() and shutil.which("cargo")):
    pytest.skip(
        "needs cargo + built mcps-proxy and mcps-demo-fileserver "
        "(cargo build -p mcps-proxy -p mcps-demo-fileserver)",
        allow_module_level=True,
    )

# Deterministic DemoFixtures defaults (only the TLS certs vary per run).
SIGNER_SEED = bytes([1] * 32)
SERVER_SEED = bytes([2] * 32)
SIGNER, SIGNER_KEY = "did:example:agent-1", "key-1"
SERVER, SERVER_KEY = "did:example:server-1", "server-key-1"
AUDIENCE, SERVER_NAME = "did:example:server-1", "proxy.internal"
ON_BEHALF_OF = "did:example:user-1"
FILE_TEXT = "hello from the inner fileserver\n"


@pytest.fixture(scope="module")
def proxy():
    out = tempfile.mkdtemp(prefix="mcps_mtls_sess_fx_")
    demo = tempfile.mkdtemp(prefix="mcps_mtls_sess_root_")
    (Path(demo) / "greeting.txt").write_text(FILE_TEXT)
    subprocess.run(
        ["cargo", "run", "-q", "-p", "mcps-demo", "--example", "emit_mtls_fixtures", "--", out],
        cwd=ROOT, check=True, capture_output=True,
    )
    p = subprocess.Popen(
        [str(PROXY),
         "--bind", "127.0.0.1:0", "--audience", AUDIENCE,
         "--server-signer", SERVER, "--server-key-id", SERVER_KEY,
         "--max-clock-skew", "300", "--expected-version-policy", "draft-02-only",
         "--key-source", "file", "--signing-key-seed", f"{out}/signing_seed",
         "--tls-cert", f"{out}/server_cert.pem", "--tls-key", f"{out}/server_key.pem",
         "--client-ca", f"{out}/client_ca.pem", "--trust", f"{out}/trust.json",
         "--max-client-cert-lifetime", "175200h", "--transport-binding", "none",
         "--inner-working-dir", demo,
         "--inner-command", str(FILESERVER), "--demo-root", demo],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    port = None
    deadline = time.time() + 30
    while time.time() < deadline:
        line = p.stderr.readline()
        if not line:
            break
        if "listening on 127.0.0.1:" in line:
            port = int(line.split("listening on 127.0.0.1:")[1].split()[0])
            break
    threading.Thread(target=lambda: [None for _ in p.stderr], daemon=True).start()
    if port is None:
        p.terminate()
        pytest.fail("mcps-proxy did not report a listening port")
    try:
        yield {"port": port, "out": out, "demo": demo}
    finally:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
        shutil.rmtree(out, ignore_errors=True)
        shutil.rmtree(demo, ignore_errors=True)


def _config(resolver, expected_server_signer):
    return mcps_sdk.McpsConfig(
        signer=mcps_sdk.Signer.software(SIGNER_SEED, signer_id=SIGNER, key_id=SIGNER_KEY),
        policy=mcps_sdk.SignerPolicy(SIGNER, environment="dev-test", require_mcps=True),
        resolver=resolver,
        audience=AUDIENCE,
        on_behalf_of=ON_BEHALF_OF,
        # Real authorization-binding provider: the digest is SHA-256 of the actual
        # decoded capability bytes, computed by the audited core — not a constant.
        # The route is fail-closed to opaque-bytes only. The production proxy accepts
        # the well-formed binding (bind-not-interpret) over real mTLS.
        authorization=mcps_sdk.OpaqueBytesProvider(b"demo-capability-token-decoded-bytes"),
        authorization_policy=mcps_sdk.AuthorizationBindingPolicy.opaque_only(),
        expected_server_signer=expected_server_signer,
        enforcement_mode="require_mcps",
        ttl_seconds=300,
    )


def _trusting_resolver():
    r = mcps_sdk.TrustResolver()
    r.insert_dev_seed(SERVER, SERVER_KEY, SERVER_SEED)
    return r


def _conn(proxy, config):
    return mcps_sdk.connect_mtls_http(
        "127.0.0.1", proxy["port"], config,
        server_ca=f"{proxy['out']}/server_ca.pem",
        client_cert=f"{proxy['out']}/client_cert.pem",
        client_key=f"{proxy['out']}/client_key.pem",
        server_name=SERVER_NAME,
    )


def test_clientsession_initialize_and_call_over_mtls(proxy):
    """A real ClientSession initializes and calls read_file end-to-end over real
    mTLS: initialize is a signed request, the server-signed responses are verified +
    stripped, and the file content comes back through plain MCP."""

    async def run():
        config = _config(_trusting_resolver(), expected_server_signer=SERVER)
        with anyio.fail_after(30):
            async with _conn(proxy, config) as session:
                init = await session.initialize()
                assert init.serverInfo.name == "mcps-demo-fileserver"
                assert init.protocolVersion == "2025-06-18"
                result = await session.call_tool("read_file", {"path": "greeting.txt"})
                assert result.content[0].text == FILE_TEXT

    anyio.run(run)


def _sm(rid, method, params):
    raw = json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
    return SessionMessage(JSONRPCMessage.model_validate_json(raw))


def test_http_transport_drives_delete_files_continuation_over_mtls(proxy):
    """ADR-047 continuation END TO END over real mTLS: `delete_files` elicits an
    InputRequiredResult, then the client answers it. The real `mcps-proxy` signs BOTH
    responses over the actual runtime request hashes, so this exercises
    `McpsHttpTransport`'s own MRT threading — `self._mrt` recorded on the elicit leg,
    bound on the answer leg — against the production PEP (not a fixture stand-in).

    Driven at the transport level (not through `ClientSession`) because the elicitation
    arrives as an InputRequiredResult *result*, which a `ClientSession` delivers but
    cannot itself continue — the application (here, the test) supplies the answer leg,
    exactly as the four-hop driver does. `initialize` is skipped: the proxy + stateless
    fileserver dispatch `tools/call` directly, as the conformance matrix proves."""

    async def run():
        config = _config(_trusting_resolver(), expected_server_signer=SERVER)
        post = mcps_sdk.make_mtls_post_sync(
            "127.0.0.1", proxy["port"],
            server_ca=f"{proxy['out']}/server_ca.pem",
            client_cert=f"{proxy['out']}/client_cert.pem",
            client_key=f"{proxy['out']}/client_key.pem",
            server_name=SERVER_NAME,
        )
        transport = mcps_sdk.McpsHttpTransport(post, config)
        with anyio.fail_after(30):
            async with transport as (read_stream, write_stream):
                # Leg 1 — elicit: no inputResponses, so the server returns an
                # InputRequiredResult and the transport records its MRT binding.
                await write_stream.send(
                    _sm("del-1", "tools/call",
                        {"name": "delete_files", "arguments": {"paths": ["greeting.txt"]}})
                )
                elicit = await read_stream.receive()
                em = json.loads(elicit.message.model_dump_json(by_alias=True, exclude_none=True))
                assert em["result"]["resultType"] == "inputRequired"
                assert "_meta" not in em["result"], "the MCP-S envelope must be stripped"
                state = em["result"]["requestState"]

                # Leg 2 — answer: inputResponses + the echoed requestState. The transport
                # must bind the recorded continuation; the proxy verifies and the
                # fileserver returns the terminal result.
                await write_stream.send(
                    _sm("del-2", "tools/call", {
                        "name": "delete_files",
                        "arguments": {"paths": ["greeting.txt"]},
                        "inputResponses": {"confirm": True},
                        "requestState": state,
                    })
                )
                terminal = await read_stream.receive()
                tm = json.loads(terminal.message.model_dump_json(by_alias=True, exclude_none=True))
                assert tm["result"]["isError"] is False
                assert tm["result"]["structuredContent"] == {
                    "deleted": ["greeting.txt"], "confirmed": True,
                }

    anyio.run(run)


def test_clientsession_fails_closed_when_server_untrusted(proxy):
    """With no trust anchor for the server signer, the genuinely-signed initialize
    response is rejected; the rejection is delivered as a JSON-RPC error correlated
    to the initialize id, so `ClientSession.initialize()` raises (it does NOT hang)."""

    async def run():
        config = _config(mcps_sdk.TrustResolver(), expected_server_signer=None)
        with anyio.fail_after(30):
            async with _conn(proxy, config) as session:
                with pytest.raises(McpError) as excinfo:
                    await session.initialize()
                assert excinfo.value.error.message == "mcps.actor_binding_failed"

    anyio.run(run)
