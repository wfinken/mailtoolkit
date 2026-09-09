# Validation record

Source revision: `df15ac5ecd95603536b87e91285213be64bfc99e`.

[GitHub Actions run](https://github.com/wfinken/mailtoolkit/actions/runs/34416816972).

## Automated coverage

- Thirteen Rust unit tests: DNS reverse names, policy parsing, unsigned DKIM handling, message generation/header injection, SMTP parsing/dot-stuffing/probing, storage path validation, shell quoting, and result classification.
- CLI subprocess tests: message build/inspection, JSON schema, history, report export, invalid profiles, header injection, and dry runs.
- Isolated SMTP integration tests: authenticated delivery, STARTTLS and implicit TLS, custom CA trust, untrusted-certificate and hostname-mismatch rejection, recipient rejection, timeout handling, and credential redaction.
- Strict Clippy and Rust formatting checks.
- SwiftUI compilation and native macOS app packaging with a local ad-hoc signature.

All automated gates passed on Ubuntu 22.04 (x86_64), Ubuntu 24.04 (x86_64), and macOS 14 (arm64). The separate SwiftUI compilation job also passed. The run includes downloadable CLI artifacts and `Mailbench-macos-app`, containing the Apple Silicon app bundle.

The Linux CLI was also downloaded and exercised in the authoring environment against the offline CLI and local SMTP/TLS fixtures. No Rust or Swift toolchains were available there; compilation occurred in GitHub Actions.

## Limits

These checks do not establish full PRD acceptance. Manual macOS UI, keyboard, VoiceOver, Keychain prompts, and user cancellation testing remain. Production/customer email systems were not contacted. Tests use loopback SMTP servers and temporary laboratory certificates. Signed DKIM golden fixtures, comprehensive SPF recursion/limit cases, and the remaining feature work in [implementation status](IMPLEMENTATION.md) are still required.

The app is not Developer ID signed or notarized. GitHub Actions artifacts are development builds, not an official release.
