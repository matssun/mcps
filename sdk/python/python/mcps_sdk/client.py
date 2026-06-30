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

    try:
        async with connect(byte_send, byte_lines(), config) as session:
            yield session
    finally:
        process.terminate()
