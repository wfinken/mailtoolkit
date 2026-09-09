# MailToolkit / Mailbench

A local-first email infrastructure diagnostic workbench: Rust engine and CLI, with a native SwiftUI macOS interface. Mailbench is the PRD working name and executable; MailToolkit is the repository.

**Status: initial implementation, not a validated release.** Consult [implementation status](docs/IMPLEMENTATION.md) before using findings as an implementation acceptance gate. CI builds Rust on Ubuntu 22.04/24.04 and macOS and compiles the SwiftUI app. There is no telemetry, cloud backend, or automatic report upload.

## Build

Install stable Rust (including Cargo). Linux builds require a C toolchain, pkg-config, CMake, and OpenSSL development headers (`build-essential pkg-config cmake libssl-dev` on Ubuntu). Then:

```sh
cargo build --release -p mailbench
cargo test --workspace
python3 tests/cli_smoke.py target/release/mailbench
install -m 755 target/release/mailbench ~/.local/bin/mailbench
```

Ensure `~/.local/bin` exists and is on PATH. The CLI runs independently of the macOS app. Swaks is optional; native SMTP sending does not need it. RHEL/Rocky/Alma and CentOS Stream builds are provisional and not covered by CI. No Windows support is claimed.

On macOS 14+, install Xcode command-line tools and Rust, then:

```sh
bash scripts/build-macos.sh
open dist/Mailbench.app
```

The app bundle contains the Rust engine. For development, `swift run --package-path macos` also works after selecting the engine binary in Settings. The build script signs locally, without notarization. Public distribution requires an Apple signing identity and notarization.

## Common workflows

```sh
mailbench check example.com --selector halon --ip 192.0.2.20
mailbench check example.com --smtp smtp.example.com:25 --json --save
mailbench dns query example.com TXT --resolver 192.0.2.53 --tcp
mailbench mx example.com
mailbench ptr 192.0.2.20
mailbench spf check example.com
mailbench spf test example.com --ip 192.0.2.20 --mail-from test@example.com
mailbench dkim check example.com --selector halon
mailbench dkim verify received.eml
mailbench dmarc check example.com
mailbench dmarc evaluate received.eml --ip 192.0.2.20 --ehlo mail.example.com --mail-from test@example.com
mailbench smtp test smtp.example.com:25
mailbench tls smtp.example.com:465
mailbench headers received.eml
cat received.eml | mailbench message inspect -
```

`check` sends no mail. SMTP connections occur only with an explicit `--smtp` target or a selected profile. SMTP and TLS default to required STARTTLS, with implicit TLS automatically selected for port 465. `--tls-mode off` and `--no-verify` produce warnings; AUTH is forbidden unless TLS is verified. The timeout bounds the whole SMTP session, not each read.

```sh
mailbench send smtp.example.com:587 \
  --from test@example.com --to sink@example.net \
  --username test-user --password-env MAILBENCH_SMTP_PASSWORD
mailbench send smtp.example.com:25 --from test@example.com --to sink@example.net --dry-run
mailbench swaks smtp.example.com:25 --from test@example.com --to sink@example.net --dry-run
```

`send` transmits one message unless `--dry-run` is supplied. Passwords come from a named environment variable or `--password-stdin`; there is no password argument. SMTP transcripts omit AUTH payloads and DATA bodies. The Swaks builder exposes a constrained set of arguments and never invokes a shell. Swaks raw output can contain message content; review before sharing.

## Profiles and history

```sh
mailbench profile import examples/customer-a.toml
mailbench profile list
mailbench check --profile customer-a --save
mailbench history list
mailbench history show SESSION_UUID
mailbench history diff BEFORE_UUID AFTER_UUID
mailbench report SESSION_UUID --format html --output report.html
mailbench history delete SESSION_UUID
mailbench history clear --yes
mailbench config path
mailbench config validate
mailbench doctor
```

Both interfaces use `MAILBENCH_CONFIG_DIR`, then `$XDG_CONFIG_HOME/mailbench`, then `~/.config/mailbench`. History is opt-in, written with private file permissions on Unix, and retains raw customer infrastructure data until deleted. Profiles use TOML with secret environment-variable references; they reject unknown fields such as plaintext passwords. Sending from profiles and retention policies are follow-up work.

## Machine-readable contract

`--json` emits one schema-version-1 session object. Each finding contains test, target, status, summary, evidence, next steps, and duration. Unknown or unavailable facts are not synthesized. Raw third-party library debug details are evidence, not stable API fields. `--quiet`, `--verbose`, and `--no-color` are accepted; output currently contains no ANSI escapes.

Exit codes: 0 no warning/failure/error; 1 failed assertion; 2 warning; 3 argument/configuration error; 4 network/system error. Skipped tests are not passes: always inspect findings when deciding readiness. No internal-error code 5 is emitted yet. Clap syntax errors are printed to stderr, including when `--json` was requested.

## Architecture

- `crates/mailbench-core`: typed result contract, DNS, authentication, SMTP/TLS, message parsing/building, Swaks, local storage.
- `crates/mailbench-cli`: CLI orchestration and JSON interface.
- `macos`: SwiftUI navigation, forms, result/evidence inspector, transcript filtering, process cancellation, Keychain integration.
- `docs/PRD.md`: original supplied PRD, preserved verbatim.
- `docs/IMPLEMENTATION.md`: scope, validation status, and outstanding requirements.

Mail authentication delegates to [mail-auth](https://docs.rs/mail-auth/0.12.1/mail_auth/). DNS uses Hickory; native TLS uses platform trust through native-tls. No Halon-specific configuration changes are made.
