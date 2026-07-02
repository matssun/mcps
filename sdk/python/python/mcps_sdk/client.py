"""High-level entry points: open an MCP-S-secured ``ClientSession``.

``connect`` wraps a byte channel + :class:`~mcps_sdk.transport.McpsConfig` in the
adapter and hands the resulting plain-MCP streams to ``mcp.ClientSession`` — so
application code is unchanged from ordinary MCP while every request is signed and
every response verified. ``connect_stdio`` builds that byte channel from a
subprocess (the common MCP stdio case).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, Optional

from .transport import ByteSend, McpsConfig, McpsTransport


@asynccontextmanager
async def connect(
    byte_send: ByteSend,
    byte_lines: Any,
    config: McpsConfig,
    *,
    correlation: Any = None,
    clock=None,
    nonce_factory=None,
):
    """Yield an ``mcp.ClientSession`` whose traffic is MCP-S signed/verified over the
    given byte channel (``byte_send`` writes framed bytes; ``byte_lines`` is an async
    iterator of inbound newline-delimited JSON)."""
    from mcp import ClientSession  # lazy: keeps `import mcps_sdk` mcp-free

    transport = McpsTransport(
        byte_send, byte_lines, config, correlation, clock=clock, nonce_factory=nonce_factory
    )
    async with transport as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            yield session


@asynccontextmanager
async def connect_stdio(
    command: str,
    args: list[str],
    config: McpsConfig,
    *,
    env: Optional[dict] = None,
):
    """Spawn an MCP-S endpoint subprocess and open a secured session over its stdio.

    The subprocess must speak the MCP-S wire (a server-side MCP-S proxy/server). A
    full cross-process end-to-end against the Rust MCP-S server is the next slice;
    the byte plumbing here is the integration point.
    """
    import anyio

    process = await anyio.open_process(
        [command, *args], stdin=anyio.subprocess.PIPE, stdout=anyio.subprocess.PIPE, env=env
    )

    async def byte_send(data: bytes) -> None:
        await process.stdin.send(data)

    async def byte_lines():
        buffer = b""
        async for chunk in process.stdout:
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                yield line
        # Yield a final unterminated line (stdout closed without a trailing '\n')
        # rather than silently dropping the last message.
        if buffer:
            yield buffer

    try:
        async with connect(byte_send, byte_lines(), config) as session:
            yield session
    finally:
        # Close stdin then reap the subprocess so we don't leave a dangling child.
        with anyio.move_on_after(5, shield=True):
            await process.stdin.aclose()
            process.terminate()
            await process.wait()


def make_mtls_post_sync(
    host: str,
    port: int,
    *,
    server_ca: str,
    client_cert: str,
    client_key: str,
    server_name: str,
    timeout: float = 15.0,
):
    """Build a synchronous ``body -> (content_type, response_body)`` mTLS POST — one
    HTTP/1.1 POST per connection (``Connection: close``), the ``mcps-proxy`` wire.

    Shared by :func:`connect_mtls_http` and the live session tests so both drive the
    SAME socket path. The client authenticates with ``client_cert`` / ``client_key``
    (the cert's URI SAN is the MCP-S signer DID) and verifies the proxy's server
    certificate against ``server_ca`` for ``server_name``.
    """
    import socket
    import ssl

    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=server_ca)
    ctx.load_cert_chain(client_cert, client_key)

    def post_sync(body: bytes) -> "tuple[str, bytes]":
        """One mTLS HTTP/1.1 POST; returns ``(content_type, response_body)``."""
        raw = socket.create_connection((host, port), timeout=timeout)
        try:
            tls = ctx.wrap_socket(raw, server_hostname=server_name)
        except Exception:
            raw.close()
            raise
        try:
            head = (
                f"POST / HTTP/1.1\r\nHost: {server_name}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode()
            tls.sendall(head + body)
            chunks: list[bytes] = []
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
            resp = b"".join(chunks)
        finally:
            tls.close()
        head_bytes, _, resp_body = resp.partition(b"\r\n\r\n")
        content_type = ""
        for line in head_bytes.split(b"\r\n"):
            name, sep, value = line.partition(b":")
            if sep and name.strip().lower() == b"content-type":
                content_type = value.strip().decode("latin-1")
                break
        return content_type, resp_body

    return post_sync


@asynccontextmanager
async def connect_mtls_http(
    host: str,
    port: int,
    config: McpsConfig,
    *,
    server_ca: str,
    client_cert: str,
    client_key: str,
    server_name: str,
    timeout: float = 15.0,
    correlation: Any = None,
    clock=None,
    nonce_factory=None,
):
    """Yield an ``mcp.ClientSession`` whose every request is one MCP-S-signed mTLS
    POST to the production ``mcps-proxy`` (verified server-signed response).

    This is the request/response counterpart to :func:`connect_stdio`: the proxy
    serves one HTTP/1.1 POST per mTLS connection (``Connection: close``), so each
    ``ClientSession`` request opens its own connection. ``initialize`` round-trips
    as a normal signed request; client→server notifications are dropped (the
    transport has no fire-and-forget channel and the minimal proxy never pushes).

    The client authenticates with ``client_cert`` / ``client_key`` (the cert's URI
    SAN is the MCP-S signer DID) and verifies the proxy's server certificate against
    ``server_ca`` for ``server_name``.
    """
    from mcp import ClientSession  # lazy: keeps `import mcps_sdk` mcp-free

    from .http_transport import McpsHttpTransport

    post_sync = make_mtls_post_sync(
        host,
        port,
        server_ca=server_ca,
        client_cert=client_cert,
        client_key=client_key,
        server_name=server_name,
        timeout=timeout,
    )
    transport = McpsHttpTransport(
        post_sync, config, correlation, clock=clock, nonce_factory=nonce_factory
    )
    async with transport as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            yield session
