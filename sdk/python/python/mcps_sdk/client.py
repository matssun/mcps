"""High-level entry point: open an MCP-S-secured ``ClientSession``.

``connect`` is the one call most applications use — it wraps the plain transport
in :class:`~mcps_sdk.transport.McpsTransport` and hands the resulting plain-MCP
streams to ``mcp.ClientSession``, so application code is unchanged from ordinary
MCP. Everything security-relevant happens inside the transport.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from .transport import McpsPolicy, McpsTransport


@asynccontextmanager
async def connect(
    inner_transport,
    *,
    policy: McpsPolicy,
    signer,
    trust_resolver,
    binding_provider=None,
):
    """Yield an ``mcp.ClientSession`` whose traffic is MCP-S signed/verified.

    SCAFFOLD (#199): wires the adapter to ``ClientSession``; body completed once
    :class:`McpsTransport` is implemented.
    """
    # Imported here (not at module load) so `import mcps_sdk` works without a
    # live `mcp` install during scaffolding/CI of the native core alone.
    from mcp import ClientSession  # noqa: F401  (used once the body lands)

    transport = McpsTransport(
        inner_transport,
        policy=policy,
        signer=signer,
        trust_resolver=trust_resolver,
        binding_provider=binding_provider,
    )
    # TODO(#199):
    #   async with transport as (read_stream, write_stream):
    #       async with ClientSession(read_stream, write_stream) as session:
    #           yield session
    raise NotImplementedError("connect(): scaffold (#199)")
    yield  # pragma: no cover  (makes this a generator for @asynccontextmanager)
