# Implementation and release status

This is an initial source implementation of the PRD, not completion of every milestone. Do not label it v1-ready until the remaining acceptance criteria below have been implemented and tested.

## Implemented source

- Cargo workspace with shared Rust library and CLI.
- DNS record queries, MX ordering/null MX/target resolution/CNAME detection, reverse DNS and forward confirmation; custom resolver and TCP for DNS queries.
- SPF TXT inspection; independent IP evaluation through mail-auth. DKIM key parsing for RSA/Ed25519 and independent message verification. DMARC DNS policy checks and message evaluation with explicit original SMTP identity.
- Native SMTP with bounded replies and overall timeout, EHLO/HELO fallback, STARTTLS/implicit TLS, platform certificate and hostname verification, certificate metadata, AUTH PLAIN on verified TLS, source-IP binding, transcript capture, DATA dot-stuffing, and rejection handling.
- Plain/HTML UTF-8 message builder, correlation UUID, custom headers, native sending, Swaks command preview/execution, message/header/MIME inspection.
- JSON contract, TOML profiles, opt-in private history, basic session comparison, Markdown/HTML/JSON reports, dependency checks.
- Native SwiftUI app with forms and results, evidence disclosure, SMTP transcript filters, command copy, process cancellation, history/profile operations and Keychain password storage.
- Unit tests and offline CLI integration checks; Ubuntu/macOS CI configuration.

## Known limitations and required follow-up

1. Compile and test on real toolchains. The authoring environment lacked Rust and Swift; source generation is not proof of a working binary. Resolve CI errors and record results before cutting a release.
2. SPF `check` is record inspection only. Mechanism-level recursive traces, matched mechanism, accurate DNS budgets, void lookup evidence, and independent syntax-only validation are not implemented. `test` delegates the protocol result to mail-auth.
3. Authentication uses the system resolver; custom resolver support is currently restricted to explicit DNS queries. DNS AA flags/raw wire packets and independent DNSSEC validation are unavailable. Negative DNS answers currently surface as ERROR instead of distinguishing NXDOMAIN/NODATA from transport errors.
4. DKIM verification exposes provider evidence, rather than a structured canonicalization/body-hash inspector. The DNS validator does not yet enforce all optional key tags or cryptographically validate Ed25519 curve points. Signed golden fixtures, tampered-body fixtures, recursion/lookup-limit tests, and domain-alignment fixtures are required.
5. DMARC exact-domain DNS inspection does not show inherited records or external report authorization. Independent message evaluation is delegated to mail-auth. Distinguish no-policy, temporary DNS failure, and alignment failure more precisely in displayed results.
6. SMTP IO errors must be separated consistently from protocol rejection. Native TLS does not expose negotiated cipher/protocol or full chain here; those fields remain null. Add explicit protocol selection, chain/SAN views, LOGIN, secure prompt, IPv4/IPv6 selection, and live incremental IPC. STARTTLS success, trust failure, hostname mismatch, rejection, AUTH redaction and timeout integration fixtures remain required.
7. Native sending does not support attachments, multipart alternatives, SMTPUTF8 envelopes, DSN or behavioral tests. Swaks builder is intentionally constrained and not an arbitrary-argument passthrough. Authentication with Swaks, richer headers and attachments remain to implement.
8. Profile sending, global defaults, overrides, secure prompt, auto-retention, selective report redaction, search, polished diff presentation and export bundles remain. Report exports contain raw evidence and must be reviewed before sharing. Large history lists are not paginated.
9. macOS needs build/UI/accessibility testing. Profile editing, rich header/MIME tables, drag/drop, structured history browsing, dedicated DKIM message view, full DMARC controls, report redaction UI and automated UI tests remain. Keychain items currently have no in-app deletion control. Child processes spawned by Swaks may outlive a GUI cancellation; use native sending until process-group cancellation is added.
10. PRD v0.2/v0.3 capabilities remain: sink adapter interface and implementations, end-to-end verify, suites/assertions, MTA-STS/TLS-RPT, Halon API adapter, ARC/DANE, relay/behavioral tests and recipe workflows.
11. No release binaries, lockfile, SBOM, notarization or signed release pipeline yet. Pin dependencies after successful resolution and commit Cargo.lock. Ubuntu 22.04/24.04 and macOS 14 are CI targets, not certified support until green runs exist. RHEL-family support is provisional; no retired CentOS release is promised.

## Validation gates

- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo build --release -p mailbench`
- `python3 tests/cli_smoke.py target/release/mailbench`
- `swift build --package-path macos`
- Manual macOS app, Keychain, cancellation, VoiceOver and keyboard review.
- Authorized lab SMTP/TLS/authentication and sink-delivery fixture coverage.
