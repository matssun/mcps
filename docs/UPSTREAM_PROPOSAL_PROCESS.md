<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-S Upstream Proposal Process

This document describes the intended path for proposing MCP-S to the MCP project.

## Status

MCP-S is currently an experimental third-party extension proposal. It should not be described as official MCP unless accepted through the relevant governance process.

## Recommended sequence

1. Finish the internal security and test evidence package.
2. Publish or prepare the MCP-S repository under a third-party extension identifier.
3. Clearly label the project as experimental and unofficial.
4. Prepare a concise extension proposal brief.
5. Open a discussion with the MCP community.
6. Seek a maintainer sponsor if the process requires one.
7. Submit a formal proposal according to the MCP project's current contribution process.
8. Respond to review feedback and adjust the spec, implementation, and conformance tests.
9. Only use official extension identifiers if accepted.

## Extension identifier

Incubation identifier:

```text
se.syncom/mcps
```

Do not use official MCP-controlled identifiers unless accepted.

## Proposal package contents

The proposal package should include:

- motivation and threat model;
- current security boundary;
- normative message/envelope schema;
- canonicalization and signature rules;
- replay/freshness model;
- trust resolver interface;
- authorization profile model;
- transport hardening model;
- conformance vectors;
- reference implementation;
- test traceability manifest;
- demo instructions;
- non-goals and deferred work.

## Do not claim

Do not claim official MCP endorsement, Anthropic endorsement, ecosystem standard status, horizontal-scale protection, enterprise key custody, OS sandboxing, or full certificate revocation unless those are explicitly accepted and implemented.
