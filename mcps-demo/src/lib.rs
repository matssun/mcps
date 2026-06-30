//! `mcps-demo` — the MCP-S single-node demo harness crate (MCPS-EPIC-P6.5).
//!
//! This umbrella crate holds the host/ambassador side of the demo. For MCPS-046
//! (Child Issue 2) it provides [`DemoHostClient`], a thin demo client built on
//! the EXISTING `mcps-host` [`HostSession`](mcps_host::HostSession): it signs
//! MCP-S requests (nonce from an injected RNG, freshness from an injected clock +
//! configured lifetime), tracks the `request_hash` by JSON-RPC id, and verifies a
//! signed server response against the STORED hash. The language model never holds
//! keys — the client exposes the signer identity but NO private-key accessor.
//!
//! Crate boundary (ADR-MCPS-001): this crate lives INSIDE the `components/mcps`
//! workspace and depends only on its sibling in-workspace crates (`mcps-host`,
//! `mcps-core`) plus the pure serde subset already pinned by the workspace — no
//! crate outside the workspace and no Python component.
//!
//! Transport (ADR-MCPS-015): the demo client produces and consumes raw JSON-RPC
//! bytes. Any local stdio piping for the end-to-end demo belongs HERE, in the
//! demo crate — never in `mcps-host`, which stays networking/async-free. Wiring
//! the request/response through `mcps-proxy` is the subject of later issues
//! (#3925 / #3927 / #3928).

pub mod client;
pub mod demo_authorization;
pub mod demo_fixtures;
pub mod demo_paths;
pub mod demo_proxy;
pub mod e2e_flow;
pub mod e2e_persistent_flow;
pub mod mtls_client;

pub use client::DemoHostClient;
pub use e2e_flow::run_positive_e2e;
pub use e2e_flow::E2eError;
pub use e2e_flow::E2eOutcome;
pub use e2e_flow::E2E_ON_BEHALF_OF;
pub use e2e_flow::E2E_PATH;
pub use e2e_flow::E2E_REQUEST_ID;
pub use e2e_flow::E2E_TOOL;
pub use e2e_persistent_flow::assemble_assertions;
pub use e2e_persistent_flow::count_inner_spawns;
pub use e2e_persistent_flow::independently_verify_response;
pub use e2e_persistent_flow::inner_received_id;
pub use e2e_persistent_flow::run_persistent_e2e;
pub use e2e_persistent_flow::server_response_public_key;
pub use e2e_persistent_flow::PersistentCallOutcome;
pub use e2e_persistent_flow::PersistentE2eAssertions;
pub use e2e_persistent_flow::PersistentE2eError;
pub use e2e_persistent_flow::PersistentE2eEvidence;
pub use e2e_persistent_flow::PersistentE2eOutcome;
pub use e2e_persistent_flow::PERSISTENT_DENIED_ID;
pub use e2e_persistent_flow::PERSISTENT_ECHO_1_ID;
pub use e2e_persistent_flow::PERSISTENT_ECHO_2_ID;
pub use e2e_persistent_flow::PERSISTENT_LIST_ID;
pub use e2e_persistent_flow::PERSISTENT_ON_BEHALF_OF;
pub use e2e_persistent_flow::TOOL_ECHO;
pub use e2e_persistent_flow::TOOL_LIST_ITEMS;
pub use e2e_persistent_flow::TOOL_RESET_ITEMS;
pub use demo_paths::demo_inner_binary;
pub use demo_paths::demo_root_dir;
pub use demo_fixtures::DemoFixtureFiles;
pub use demo_fixtures::DemoFixtureSpec;
pub use demo_fixtures::DemoFixtures;
pub use demo_authorization::build_demo_proxy_with_policy;
pub use demo_authorization::demo_policy_evaluator;
pub use demo_authorization::demo_revocation_source;
pub use demo_authorization::mint_demo_grant;
pub use demo_authorization::mint_demo_role_grant;
pub use demo_authorization::DemoGrant;
pub use demo_authorization::DemoGrantSpec;
pub use demo_authorization::DemoRole;
pub use demo_authorization::DemoRoleGrantSpec;
pub use demo_authorization::DEMO_METHOD;
pub use demo_authorization::DEMO_TOOL_NAME;
pub use demo_proxy::build_demo_proxy;
pub use demo_proxy::demo_inner_command;
pub use demo_proxy::demo_inner_launch;
pub use demo_proxy::DemoProxyConfig;
pub use mtls_client::MtlsClientRunner;
pub use mtls_client::RoundTripOutcome;
pub use mtls_client::RunnerError;
