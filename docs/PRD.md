# Product Requirements Document

# Email Testing Toolkit

**Working Name:** Mailbench
**Product Type:** CLI + native macOS application
**Primary Audience:** Email infrastructure engineers, implementation/support engineers, deliverability engineers, system administrators
**Primary Environment:** Halon MTA implementations, while remaining useful with any standards-compliant SMTP infrastructure
**Status:** Initial PRD / MVP definition

---

# 1. Overview

Mailbench is a comprehensive email infrastructure testing and diagnostics toolkit designed for engineers responsible for deploying, validating, troubleshooting, and supporting email systems.

The product consists of:

1. A powerful command-line interface.
2. A modern native macOS desktop application.
3. A shared testing engine used by both interfaces.

Mailbench should consolidate the collection of commands, scripts, DNS lookups, SMTP probes, `swaks` invocations, TLS inspections, authentication checks, and manual verification steps normally required when validating an email environment.

Instead of an engineer needing to remember commands such as:

```bash
dig TXT example.com
dig MX example.com
dig TXT selector._domainkey.example.com
swaks --server smtp.example.com ...
openssl s_client -starttls smtp ...

```

the engineer should be able to run:

```bash
mailbench check example.com

```

and receive a structured assessment of the email environment.

Mailbench should also allow individual tools to be invoked independently.

Examples:

```bash
mailbench dns mx example.com
mailbench spf check example.com
mailbench dkim check example.com --selector halon
mailbench dmarc check example.com
mailbench smtp test smtp.example.com
mailbench tls smtp.example.com:25
mailbench send ...

```

The macOS application exposes the same capabilities through a polished visual interface.

---

# 2. Problem

Email implementation testing currently involves many disconnected tools.

An engineer may need to use:

- `swaks`
- `dig`
- `host`
- `nslookup`
- `openssl`
- `curl`
- WHOIS/RDAP
- manual SMTP sessions
- SPF inspection tools
- DKIM verification tools
- DMARC analyzers
- certificate inspection
- IP/reverse DNS checking
- message header analysis
- sink/mailbox inspection
- custom shell scripts

Each tool provides useful information, but there is no unified workflow.

The engineer must also understand how the results relate to each other.

For example:

```text
Does the sending IP have PTR?

    ↓

Does the PTR hostname resolve back to the IP?

    ↓

Does EHLO match an appropriate hostname?

    ↓

Does SPF authorize the sending IP?

    ↓

Does the DKIM selector exist?

    ↓

Does the message actually contain a valid DKIM signature?

    ↓

Are SPF/DKIM aligned with the From domain?

    ↓

What does DMARC therefore do?

    ↓

Did STARTTLS negotiate correctly?

    ↓

Did Halon accept and route the message?

    ↓

Did the sink receive it?

    ↓

Are the resulting headers and authentication results correct?

```

Mailbench turns this chain into a repeatable test suite.

---

# 3. Product Goals

## 3.1 Primary Goal

Allow an engineer to quickly answer:

> "Is this email environment configured correctly, and if not, exactly what is wrong?"

## 3.2 Secondary Goals

Mailbench should:

- dramatically reduce repetitive manual testing;
- provide consistent implementation verification;
- make complex email diagnostics easier to interpret;
- preserve raw protocol information for advanced troubleshooting;
- produce shareable test reports;
- provide both CLI and graphical workflows;
- work particularly well with Halon deployments;
- remain useful against arbitrary SMTP servers;
- support repeatable customer/environment profiles;
- correlate DNS, SMTP, TLS, authentication, and delivery information;
- make it difficult to overlook common implementation problems.

---

# 4. Non-Goals

Mailbench is not intended to be:

- an MTA;
- an email client;
- a production monitoring platform;
- a replacement for Halon;
- a bulk email sender;
- a marketing deliverability platform;
- a spam campaign testing service;
- a DNS management system.

Mailbench observes, tests, validates, and reports.

It should not modify DNS or production MTA configuration automatically.

---

# 5. Design Principles

## 5.1 Engineers First

Do not hide technical details.

A result should have a human-readable interpretation while always allowing access to the underlying evidence.

Example:

```text
✓ SPF PASS

example.com authorizes 192.0.2.20

Matched mechanism:
  ip4:192.0.2.0/24

DNS lookups:
  3 / 10

Evaluation:
  v=spf1 include:_spf.example.net ip4:192.0.2.0/24 -all

```

## 5.2 One Engine, Two Interfaces

The CLI and macOS application must use the same underlying test engine.

A DNS test performed from the GUI must behave identically to:

```bash
mailbench dns ...

```

## 5.3 Useful Defaults, Advanced Controls

A basic test should require minimal input.

Advanced engineers should still be able to control:

- HELO/EHLO
- MAIL FROM
- From header
- RCPT TO
- source IP
- SMTP port
- TLS behavior
- authentication
- headers
- body
- DNS resolver
- timeout
- IPv4/IPv6
- DKIM selector
- message content
- protocol behavior

## 5.4 Raw Data Is Sacred

Never replace raw diagnostic data with an interpretation.

Show both.

## 5.5 Explain Failures

Avoid:

```text
SPF: FAIL

```

Prefer:

```text
✗ SPF FAIL

192.0.2.20 is not authorized to send mail for example.com.

SPF record:
v=spf1 include:_spf.example.net -all

The tested IP did not match any permitted mechanism before "-all".

Suggested investigation:
• Verify the intended outbound IP.
• Check whether the IP should be included directly or through an include.

```

Do not automatically change configuration.

---

# 6. Proposed Architecture

## 6.1 Shared Core

Recommended architecture:

```text
                ┌───────────────────┐
                │   macOS SwiftUI   │
                │    Application    │
                └─────────┬─────────┘
                          │
                     JSON / IPC
                          │
                ┌─────────▼─────────┐
                │                   │
                │ Mailbench Engine  │
                │      (Rust)       │
                │                   │
                └─────────┬─────────┘
                          │
              ┌───────────┴───────────┐
              │                       │
       ┌──────▼──────┐        ┌──────▼──────┐
       │     CLI     │        │ Test Modules │
       └─────────────┘        └──────────────┘

```

Recommended technologies:

### Core / CLI

**Rust**

Reasons:

- single distributable binary;
- excellent networking capabilities;
- strong concurrency;
- predictable performance;
- excellent CLI ecosystem;
- macOS/Linux support;
- easy structured JSON output;
- suitable for DNS/TLS/protocol parsing.

Suggested libraries should be evaluated during implementation rather than locked by this PRD.

### macOS

**Swift + SwiftUI**

The macOS app should feel native rather than like a web application packaged inside a desktop shell.

The GUI may communicate with the Mailbench engine using a stable JSON protocol.

Example:

```bash
mailbench check example.com --json

```

This also creates a useful machine-readable interface for future integrations.

---

# 7. CLI Design

Main executable:

```bash
mailbench

```

Alternative short binary name may be selected later.

Top-level structure:

```text
mailbench
├── check
├── send
├── smtp
├── dns
├── spf
├── dkim
├── dmarc
├── tls
├── ptr
├── mx
├── message
├── headers
├── auth
├── sink
├── trace
├── profile
├── suite
└── report

```

---

# 8. Full Environment Check

The flagship command:

```bash
mailbench check example.com

```

Optional:

```bash
mailbench check example.com \
  --smtp smtp.example.com \
  --ip 192.0.2.10 \
  --selector halon

```

The engine should automatically discover as much information as possible.

Example:

```text
MAILBENCH
Environment Check: example.com

DNS
✓ A records
✓ AAAA records
✓ MX records
✓ MX targets resolve
✓ Nameservers reachable

Sending Identity
✓ PTR exists
✓ Forward-confirmed reverse DNS
✓ HELO hostname resolves
✓ HELO/PTR relationship

SPF
✓ Record found
✓ Syntax valid
✓ Sending IP authorized
✓ 4/10 DNS lookups
✓ No recursive include loop

DKIM
✓ Selector found: halon
✓ Record valid
✓ Public key valid
✓ RSA 2048-bit

DMARC
✓ Record found
✓ Syntax valid
✓ SPF alignment
✓ DKIM alignment
✓ Policy: reject

SMTP
✓ TCP connection
✓ EHLO
✓ STARTTLS
✓ PIPELINING
✓ 8BITMIME
✓ SMTPUTF8
✓ SIZE

TLS
✓ TLS 1.3
✓ Certificate valid
✓ Hostname valid
✓ Chain trusted
✓ Expires in 74 days

DELIVERY
✓ Message accepted
✓ Queue handoff
✓ Message received by sink
✓ DKIM signature valid after delivery

Overall: PASS

26 passed
0 warnings
0 failures

Completed in 2.41s

```

---

# 9. DNS Toolkit

Mailbench should contain a complete DNS troubleshooting interface.

Commands:

```bash
mailbench dns a example.com
mailbench dns aaaa example.com
mailbench dns mx example.com
mailbench dns txt example.com
mailbench dns ptr 192.0.2.10
mailbench dns cname example.com
mailbench dns ns example.com
mailbench dns soa example.com
mailbench dns srv example.com
mailbench dns caa example.com

```

Generic query:

```bash
mailbench dns query example.com TXT

```

Options:

```text
--resolver
--tcp
--dnssec
--trace
--timeout
--json

```

The GUI should show:

- record
- value
- TTL
- authoritative status
- DNSSEC status where applicable
- resolver used
- response time

Provide a raw DNS response inspector.

---

# 10. MX Analysis

Command:

```bash
mailbench mx example.com

```

Tests:

- MX existence
- null MX detection
- preference ordering
- duplicate MX records
- MX target resolution
- IPv4 addresses
- IPv6 addresses
- CNAME-related problems
- SMTP connectivity to MX hosts
- port 25 reachability
- banner collection
- STARTTLS support

Example:

```text
MX                    PREF    IPv4          SMTP    TLS
mx1.example.com       10      192.0.2.10    ✓       ✓
mx2.example.com       20      192.0.2.11    ✓       ✓

```

---

# 11. Reverse DNS

Command:

```bash
mailbench ptr 192.0.2.20

```

Perform:

1. PTR lookup.
2. Resolve resulting hostname.
3. Compare A/AAAA results against original IP.
4. Report forward-confirmed reverse DNS.

Example:

```text
192.0.2.20
   ↓ PTR
mailout.example.com
   ↓ A
192.0.2.20

✓ Forward-confirmed reverse DNS

```

---

# 12. SPF Toolkit

Commands:

```bash
mailbench spf check example.com
mailbench spf test example.com --ip 192.0.2.20
mailbench spf trace example.com --ip 192.0.2.20

```

Validate:

- SPF record existence
- multiple SPF records
- syntax
- mechanisms
- modifiers
- includes
- redirects
- recursion
- DNS lookup count
- void lookups
- IPv4
- IPv6
- `a`
- `mx`
- `include`
- `exists`
- `ptr` warnings/deprecation considerations
- `all`
- macros where practical
- qualifier behavior

The most important feature is **SPF evaluation tracing**.

Example:

```text
example.com
└── include:_spf.example.net
    ├── ip4:192.0.2.0/24       MATCH
    └── include:_spf2.example.net

Result: PASS

```

Display DNS lookup usage:

```text
DNS lookup budget

██████░░░░ 6 / 10

```

Warnings should appear before an SPF deployment approaches protocol limits.

---

# 13. DKIM Toolkit

Commands:

```bash
mailbench dkim check example.com --selector halon
mailbench dkim inspect selector._domainkey.example.com
mailbench dkim verify message.eml

```

Validate DNS key:

- selector exists
- TXT retrieval
- DKIM syntax
- version
- key type
- public key parsing
- empty/revoked key
- RSA key length
- Ed25519 support where applicable
- malformed tags

Message verification should:

- parse DKIM-Signature headers;
- identify selector/domain;
- retrieve public key;
- canonicalize headers/body;
- calculate body hash;
- verify signature;
- show signed headers;
- identify modifications causing validation failure.

Example:

```text
DKIM Signature #1

Domain:      example.com
Selector:    halon
Algorithm:   rsa-sha256
Canonical:   relaxed/relaxed
Key:         2048-bit

Body hash:   PASS
Signature:   PASS
Alignment:   PASS

Signed headers:
From
To
Subject
Date
Message-ID
MIME-Version
Content-Type

```

---

# 14. DMARC Toolkit

Commands:

```bash
mailbench dmarc check example.com
mailbench dmarc evaluate message.eml

```

Validate:

- `_dmarc` TXT lookup
- syntax
- policy
- subdomain policy
- percentage
- aggregate reporting destinations
- forensic/failure reporting configuration where relevant
- SPF alignment mode
- DKIM alignment mode

Message evaluation:

```text
Header From:
example.com

SPF:
mailfrom.example.com
PASS
Alignment: PASS

DKIM:
d=example.com
PASS
Alignment: PASS

DMARC:
PASS

```

---

# 15. SMTP Testing

SMTP testing is one of the core product areas.

Command:

```bash
mailbench smtp test smtp.example.com

```

Default ports:

```text
25
465
587

```

Allow explicit:

```bash
mailbench smtp test smtp.example.com:2525

```

Tests:

- TCP connectivity
- SMTP banner
- EHLO
- HELO fallback
- advertised extensions
- STARTTLS
- implicit TLS
- AUTH advertisement
- SIZE
- PIPELINING
- 8BITMIME
- SMTPUTF8
- DSN
- CHUNKING
- REQUIRETLS where supported
- connection timing

Show exact conversation:

```text
S: 220 smtp.example.com ESMTP
C: EHLO test.mailbench.local
S: 250-smtp.example.com
S: 250-PIPELINING
S: 250-SIZE 52428800
S: 250-STARTTLS
S: 250 SMTPUTF8

```

GUI should have a **Protocol Transcript** panel resembling a developer console/network inspector.

---

# 16. Swaks Integration

Swaks remains extremely useful and should be treated as a first-class external tool.

Mailbench should detect:

```bash
which swaks

```

and report its version.

Provide a friendly wrapper:

```bash
mailbench send

```

which can generate and execute an appropriate Swaks invocation.

Also expose:

```bash
mailbench swaks

```

for advanced usage.

The GUI should include a **Swaks Builder**.

Fields:

```text
Server
Port
TLS mode
EHLO
MAIL FROM
RCPT TO
From
To
Subject
Body
Authentication
Username
Password
Custom headers
Attachments

```

As options change, show the generated command:

```bash
swaks \
  --server smtp.example.com \
  --port 25 \
  --from sender@example.com \
  --to sink@example.net \
  --header "X-Mailbench-ID: ..."

```

Provide:

**Copy Command**

and:

**Run Test**

---

# 17. Native SMTP Sender

Mailbench should eventually contain its own SMTP implementation for routine tests.

Swaks integration remains available because engineers may need exact Swaks behavior or want a command they can reproduce elsewhere.

Native mode enables:

- structured SMTP results;
- better GUI integration;
- precise timing;
- automatic transcript capture;
- programmatic test assertions.

---

# 18. TLS Testing

Command:

```bash
mailbench tls smtp.example.com:25

```

Tests:

- STARTTLS advertisement
- TLS negotiation
- TLS protocol
- certificate chain
- certificate validity
- hostname verification
- SAN
- issuer
- expiration
- signature algorithm
- negotiated cipher
- key exchange information
- certificate chain completeness

Show:

```text
smtp.example.com:25

STARTTLS        PASS
Protocol        TLS 1.3
Cipher          ...
Certificate     PASS
Hostname        PASS
Chain           PASS
Expires         2026-12-19
Days remaining  101

```

Allow:

```bash
--protocol
--sni
--no-verify
--show-cert

```

`--no-verify` should visibly indicate that verification has intentionally been disabled.

---

# 19. Additional Transport Security

Advanced checks should include:

## MTA-STS

```bash
mailbench mta-sts example.com

```

Check:

- `_mta-sts` TXT record
- policy ID
- HTTPS policy retrieval
- policy syntax
- mode
- MX patterns
- max age

## TLS-RPT

```bash
mailbench tls-rpt example.com

```

Validate `_smtp._tls`.

## DANE

```bash
mailbench dane example.com

```

Where DNSSEC/DANE conditions allow useful validation.

---

# 20. Message Builder

Both CLI and GUI should support generating test messages.

Templates:

- plain text
- HTML
- multipart alternative
- attachment
- UTF-8
- large message
- empty body
- custom headers
- malformed message
- bounce/DSN-related scenarios
- SMTPUTF8 test

Every generated message should optionally contain:

```text
X-Mailbench-ID: <UUID>

```

and a distinctive subject:

```text
[MAILBENCH] SMTP Test <short-id>

```

This enables correlation with the receiving sink.

---

# 21. Sink Integration

Sink verification is a major product capability.

Mailbench should support configurable sink adapters.

A test workflow:

```text
Mailbench
   │
   │ SMTP
   ▼
Halon MTA
   │
   │ delivery
   ▼
Test Sink
   │
   │ lookup X-Mailbench-ID
   ▼
Mailbench

```

Every test gets a UUID.

Example:

```text
X-Mailbench-ID: 0199f470-...

```

Mailbench submits the message and waits for the sink to observe that ID.

Result:

```text
Submission
✓ Halon accepted message

Delivery
✓ Sink received message
  842 ms after submission

Message integrity
✓ Message-ID preserved
✓ From preserved
✓ DKIM present
✓ DKIM valid
✓ Body preserved

```

Sink integrations should use an adapter interface.

Potential adapters:

- generic IMAP
- HTTP/API sink
- local Maildir
- `.eml` directory
- custom adapter/plugin

No particular commercial sink should be hard-coded into the architecture.

---

# 22. Message Header Analyzer

Command:

```bash
mailbench headers message.eml

```

or:

```bash
cat message.eml | mailbench headers -

```

Parse:

- Received chain
- Authentication-Results
- DKIM-Signature
- ARC headers
- Return-Path
- Message-ID
- Date
- From
- Sender
- Reply-To
- MIME headers
- List-Unsubscribe
- List-Unsubscribe-Post
- X-\* headers

Create a visual delivery path:

```text
client.example
    │
    │ 18 ms
    ▼
submission.example
    │
    │ TLS 1.3
    ▼
outbound.example
    │
    │ DKIM signed
    ▼
sink.example

```

Flag suspicious inconsistencies.

---

# 23. Authentication-Results Analyzer

Parse RFC-style Authentication-Results information.

Present:

```text
SPF       PASS
DKIM      PASS
DMARC     PASS
ARC       PASS

```

Allow expansion:

```text
SPF
  smtp.mailfrom = example.com
  client-ip = 192.0.2.20

DKIM
  header.d = example.com
  header.s = halon

DMARC
  header.from = example.com

```

Compare results with Mailbench's independent evaluation where possible.

If they differ:

```text
⚠ Authentication result disagreement

Receiver reports:
SPF PASS

Mailbench evaluation:
SPF FAIL

Investigate:
• evaluated IP
• MAIL FROM
• DNS resolver differences
• DNS propagation/cache

```

---

# 24. ARC Inspection

Advanced message analysis should support:

```bash
mailbench arc verify message.eml

```

Inspect:

- ARC-Seal
- ARC-Message-Signature
- ARC-Authentication-Results
- chain ordering
- cryptographic validation
- chain status

---

# 25. SMTP Behavioral Tests

Create reusable tests for unusual or important SMTP behavior.

Examples:

```text
Basic delivery
Invalid recipient
Null MAIL FROM
Multiple recipients
Mixed valid/invalid recipients
Large message
8-bit body
UTF-8 address
Long header
Long line
Missing Message-ID
Missing Date
Duplicate headers
STARTTLS required
No STARTTLS
AUTH success
AUTH failure
Connection timeout
RCPT rejection
DATA rejection

```

These should be organized as test cases rather than improvised commands.

Example:

```bash
mailbench suite smtp-basic --profile customer-a

```

---

# 26. Relay Testing

Provide controlled checks for relay behavior.

Examples:

```text
Local → Local
Local → External
External → Local
External → External
Authenticated → External

```

Results:

```text
External → External

Expected: REJECT
Actual:   550 Relay denied

✓ PASS

```

Mailbench must never treat an open relay as desirable.

---

# 27. SMTP Authentication

Optional authentication testing:

- PLAIN
- LOGIN
- CRAM mechanisms where appropriate
- OAuth-related mechanisms as future work

Credentials must never appear in logs or reports unless explicitly requested.

macOS credentials should use **Keychain**.

CLI credentials should support:

- environment variable
- stdin
- secure prompt
- OS credential storage where practical

Avoid:

```bash
--password hunter2

```

where shell history would expose credentials.

---

# 28. Profiles

Profiles allow repeatable customer/environment tests.

Example:

```yaml
name: customer-a

domain: example.com

smtp:
  host: outbound.example.com
  port: 25
  ehlo: mail.example.com

sending:
  ip: 192.0.2.20
  mail_from: test@example.com
  recipient: sink@example.net

dkim:
  selector: halon

sink:
  adapter: imap
  host: sink.example.net

```

Usage:

```bash
mailbench check --profile customer-a

```

Profiles should support:

- global defaults
- environment-specific overrides
- secret references
- tags

Secrets must not be stored directly in plaintext profiles by default.

---

# 29. Test Suites

Users should be able to define suites.

Example:

```yaml
name: implementation-validation

tests:
  - dns
  - ptr
  - mx
  - spf
  - dkim
  - dmarc
  - smtp
  - tls
  - delivery
  - sink

```

Run:

```bash
mailbench suite run implementation-validation

```

---

# 30. Assertions

Tests should support explicit expectations.

Example:

```yaml
smtp:
  require_starttls: true
  require_extensions:
    - PIPELINING
    - SMTPUTF8

spf:
  expected: pass

dkim:
  expected_selector: halon

dmarc:
  expected_policy: reject

```

This transforms Mailbench from an exploratory tool into a repeatable implementation validation framework.

---

# 31. Reports

Generate reports:

```bash
mailbench report <session>

```

Formats:

```text
terminal
JSON
Markdown
HTML

```

Future:

```text
PDF

```

Example Markdown:

```markdown
# Email Environment Validation

Domain: example.com
Date: 2026-09-09

## Summary

PASS: 24
WARN: 2
FAIL: 1

## Failure

### PTR

192.0.2.20 does not have a PTR record.

```

Reports should optionally redact:

- credentials
- internal IP addresses
- recipient addresses
- message contents
- hostnames
- authentication tokens

---

# 32. JSON Output

Every major command must support:

```bash
--json

```

Example:

```json
{
  "test": "spf",
  "domain": "example.com",
  "result": "pass",
  "ip": "192.0.2.20",
  "dns_lookups": 4,
  "matched_mechanism": "ip4:192.0.2.0/24",
  "duration_ms": 37
}

```

This is essential for:

- GUI integration
- scripts
- CI/CD
- support automation
- future APIs

JSON schemas should be versioned.

---

# 33. Exit Codes

CLI behavior must be script-friendly.

Recommended:

```text
0 = all tests passed
1 = test failure
2 = warning threshold reached
3 = invalid arguments/configuration
4 = network/system error
5 = internal Mailbench error

```

Exact codes may change, but must remain documented and stable after v1.

---

# 34. Verbosity

Support:

```bash
-q
-v
-vv
-vvv

```

Example:

```text
default
Human-friendly results

-v
Additional diagnostic information

-vv
DNS/SMTP/TLS details

-vvv
Raw protocol/debug output

```

---

# 35. macOS Application

The macOS application should be a first-class product, not merely a visual wrapper around terminal output.

Use SwiftUI and standard macOS interaction patterns.

Visual direction:

**Developer tool + network inspector + modern native macOS utility.**

Avoid generic SaaS dashboard aesthetics.

No giant gradients.

No excessive cards.

No unnecessary rounded rectangles around everything.

No oversized marketing typography.

The application should feel closer to a serious engineering utility.

---

# 36. Main Navigation

Recommended sidebar:

```text
Mailbench

OVERVIEW
  Dashboard

TEST
  Environment Check
  Send Message
  SMTP Session
  Test Suites

AUTHENTICATION
  SPF
  DKIM
  DMARC
  ARC

NETWORK
  DNS
  MX
  PTR
  TLS
  MTA-STS
  DANE

ANALYZE
  Message
  Headers
  Authentication

SESSIONS
  Recent Tests
  Reports

CONFIGURATION
  Profiles
  Sinks
  Settings

```

---

# 37. Dashboard

The dashboard should prioritize action.

Top:

```text
┌──────────────────────────────────────────────────────┐
│ Domain, hostname or IP                               │
│ example.com                                  [Check] │
└──────────────────────────────────────────────────────┘

```

Recent environments:

```text
customer-a       ✓ 2 min ago
customer-b       ⚠ yesterday
lab              ✓ Monday

```

Quick actions:

```text
Send Test
SMTP Probe
DNS Lookup
Analyze Message
Run Suite

```

Do not turn the dashboard into a wall of vanity statistics.

---

# 38. Environment Results UI

Use a split view.

```text
┌──────────────────────────┬─────────────────────────────┐
│ RESULTS                  │ DETAILS                     │
│                          │                             │
│ ✓ DNS                    │ SPF                         │
│ ✓ PTR                    │                             │
│ ✓ MX                     │ Result       PASS           │
│ ✓ SPF                    │ IP           192.0.2.20     │
│ ✓ DKIM                   │ Mechanism    include:...    │
│ ✓ DMARC                  │ Lookups      4/10           │
│ ⚠ SMTP                   │                             │
│ ✓ TLS                    │ [Evaluation Tree]           │
│ ✓ Delivery               │                             │
└──────────────────────────┴─────────────────────────────┘

```

Status colors should supplement symbols/text rather than be the sole status indicator.

---

# 39. SMTP Session UI

Create a protocol-inspector experience.

```text
12:04:01.114  CONNECT  smtp.example.com:25
12:04:01.143  S ← 220 smtp.example.com ESMTP
12:04:01.144  C → EHLO mailbench.local
12:04:01.161  S ← 250-PIPELINING
12:04:01.161  S ← 250-STARTTLS
12:04:01.161  S ← 250 SMTPUTF8

```

Use:

- monospace typography
- directional indicators
- timestamps
- elapsed timing
- expandable commands
- copy capability

Filters:

```text
All | Client | Server | TLS | Errors

```

---

# 40. DNS Explorer UI

Allow:

```text
[example.com                    ] [TXT ▼] [Query]

```

Results should be presented as structured rows.

Include an optional dependency graph for SPF/DKIM/DMARC discovery.

For example:

```text
example.com
    │
    ├── SPF
    │    └── _spf.provider.com
    │           └── 192.0.2.0/24
    │
    ├── DKIM
    │    └── halon._domainkey.example.com
    │
    └── DMARC
         └── _dmarc.example.com

```

---

# 41. Message Inspector

Support:

- drag/drop `.eml`
- Open File
- paste raw message
- stdin through CLI

Tabs:

```text
Summary
Headers
Authentication
DKIM
ARC
MIME
Received Path
Raw

```

Summary:

```text
Authentication

✓ SPF
✓ DKIM
✓ DMARC
✓ ARC

Transport

4 Received hops
TLS observed
2.14 seconds total apparent transit time

Message

From
To
Subject
Message-ID
Date
Size

```

---

# 42. Command Palette

macOS should provide:

```text
⌘K

```

Search actions:

```text
Check SPF
Check DKIM
Send SMTP test
Query DNS
Analyze message
Open profile
Run implementation suite

```

Keyboard-first navigation is important for engineering users.

---

# 43. Session History

Every meaningful test can optionally become a session.

Store locally:

```text
timestamp
profile
target
tests
results
duration
generated trace ID
transcript
report metadata

```

Search:

```text
example.com
DKIM
failed
customer-a

```

Allow comparison:

```text
Customer A

Yesterday                    Today

DKIM       FAIL              PASS
SPF        PASS              PASS
PTR        FAIL              PASS
TLS        PASS              PASS

```

This is particularly valuable during implementations where DNS/configuration changes occur between tests.

---

# 44. Diff Mode

Allow comparing two test sessions.

Example:

```text
SPF

BEFORE
v=spf1 ip4:192.0.2.10 -all

AFTER
v=spf1 ip4:192.0.2.10 ip4:192.0.2.20 -all
                            +++++++++++++++++

```

Useful for validating customer changes.

---

# 45. Test Timeline

Each environment test should record timing.

Example:

```text
DNS                 34ms
SPF                 82ms
DKIM                29ms
DMARC               31ms
SMTP               240ms
TLS                310ms
Submission           92ms
Sink delivery       841ms

```

Total:

```text
1.659s

```

This may expose DNS or connection latency problems that would otherwise go unnoticed.

---

# 46. Halon-Oriented Workflow

Mailbench must remain vendor-neutral at its core.

However, it should provide optional Halon-oriented functionality because Halon environments are a primary use case.

Possible integration layer:

```text
mailbench halon ...

```

Capabilities may eventually include:

- connectivity validation
- test submission
- queue correlation
- message trace correlation
- health information
- configuration-aware validation where APIs/interfaces permit it

Halon-specific functionality should live behind a provider/adapter abstraction.

Conceptually:

```text
MTAProvider
├── GenericSMTP
└── Halon

```

Future providers could therefore be implemented without redesigning Mailbench.

---

# 47. End-to-End Implementation Test

This should ultimately become Mailbench's signature feature.

Command:

```bash
mailbench verify --profile customer-a

```

Workflow:

```text
1. Resolve DNS
2. Validate PTR
3. Evaluate SPF
4. Retrieve DKIM
5. Validate DMARC
6. Connect to Halon
7. Inspect SMTP capabilities
8. Negotiate TLS
9. Generate unique message
10. Submit message
11. Capture SMTP transaction
12. Wait for sink
13. Retrieve delivered message
14. Verify DKIM
15. Analyze Authentication-Results
16. Compare identities
17. Produce report

```

Final output:

```text
CUSTOMER-A IMPLEMENTATION

Infrastructure
✓ DNS
✓ MX
✓ PTR
✓ FCrDNS

Authentication
✓ SPF
✓ DKIM
✓ DMARC

Transport
✓ SMTP
✓ STARTTLS
✓ Certificate

Delivery
✓ Halon accepted
✓ Sink received
✓ Message integrity
✓ DKIM survived delivery

27 tests passed
0 warnings
0 failures

READY

```

If something fails:

```text
NOT READY

1 blocking issue

DKIM
✗ Message arrived without a DKIM-Signature header.

DNS key:
✓ Present

Expected selector:
halon

This suggests DNS is configured but the outbound message was not
signed using the expected selector.

Trace:
0199f470-...

```

This distinction between **DNS being configured** and **the actual message being correctly processed** is critical.

---

# 48. Test Severity

Three normal statuses:

```text
PASS
WARN
FAIL

```

Plus:

```text
SKIP
INFO
ERROR

```

Difference:

**FAIL**

The environment did not meet an assertion.

**ERROR**

Mailbench could not complete the test.

Example:

```text
FAIL
DKIM signature invalid.

ERROR
DNS resolver timed out before DKIM could be evaluated.

```

---

# 49. Security

Mailbench will interact with infrastructure and potentially credentials.

Requirements:

- credentials never logged by default;
- secrets redacted from reports;
- macOS Keychain integration;
- secure credential prompting;
- TLS verification enabled by default;
- explicit warning when certificate verification is disabled;
- no telemetry containing customer infrastructure;
- no automatic upload of test results;
- local-first session storage;
- configurable history retention;
- clear "Delete Session" and "Clear History" functionality.

Production testing should be deliberate.

Potentially disruptive tests must display warnings.

---

# 50. Privacy

Mailbench should be local-first.

Default behavior:

```text
DNS queries → configured/system resolver
SMTP → target infrastructure
Sink → configured sink
History → local machine
Reports → local machine

```

No Mailbench cloud service should be required.

This is particularly important because implementation reports may contain customer domains, hostnames, IP addresses, headers, and infrastructure information.

---

# 51. Configuration

Suggested location:

```text
~/.config/mailbench/config.toml

```

Profiles:

```text
~/.config/mailbench/profiles/

```

macOS application should use appropriate macOS application support locations internally while remaining interoperable with CLI configuration.

Provide:

```bash
mailbench config show
mailbench config edit
mailbench config path
mailbench config validate

```

---

# 52. Dependency Detection

Command:

```bash
mailbench doctor

```

Example:

```text
Mailbench Doctor

✓ DNS resolver available
✓ OpenSSL available
✓ swaks 20240103
✓ IPv4 connectivity
✓ IPv6 connectivity
✓ Keychain available
✓ Configuration valid
✓ Sink reachable

Ready.

```

External utilities should be optional whenever Mailbench has equivalent native functionality.

---

# 53. Offline / Restricted Environment Support

Implementation engineers may work through:

- VPNs
- jump hosts
- restricted networks
- SSH sessions
- customer environments

Therefore the CLI must remain useful independently of the macOS app.

It should be possible to copy the binary onto another machine and run:

```bash
mailbench check ...

```

without installing a full application stack.

---

# 54. Export Reproduction Commands

Every GUI test should expose:

**Copy CLI Command**

Example:

```bash
mailbench smtp test smtp.example.com:25 \
  --ehlo test.example.com \
  --starttls

```

Where Swaks was used:

**Copy Swaks Command**

This bridges graphical investigation and terminal troubleshooting.

---

# 55. Copy Diagnostic Bundle

A result should support:

```text
Copy Summary
Copy Raw Output
Copy Reproduction Command
Export Report
Export Diagnostic Bundle

```

A diagnostic bundle might contain:

```text
summary.md
results.json
smtp-transcript.txt
dns.json
message-redacted.eml

```

Redaction should be available before export.

---

# 56. MVP

Version 0.1 should resist trying to implement every email RFC ever written.

MVP should include:

### CLI

- DNS query
- MX analysis
- PTR/FCrDNS
- SPF validation/evaluation
- DKIM DNS validation
- DKIM message verification
- DMARC validation/evaluation
- SMTP connectivity
- EHLO capability inspection
- STARTTLS
- certificate validation
- Swaks integration
- message sending
- `.eml` analysis
- JSON output
- profiles
- environment check

### macOS

- Dashboard
- Environment Check
- DNS Explorer
- SPF
- DKIM
- DMARC
- SMTP tester
- Swaks/message builder
- TLS inspector
- Message inspector
- local history
- profiles

---

# 57. Version 0.2

Add:

- sink adapters
- end-to-end delivery verification
- session correlation
- test suites
- assertions
- reports
- Authentication-Results comparison
- session diffing
- MTA-STS
- TLS-RPT
- improved message path visualization

---

# 58. Version 0.3

Add:

- Halon integration adapter
- queue/trace correlation where supported
- ARC verification
- DANE
- advanced SMTP behavior suites
- relay validation
- performance/timing analysis
- diagnostic bundles
- plugin architecture

---

# 59. Future Ideas

Potential future features:

- Linux GUI
- Windows CLI
- SSH remote execution
- CI mode
- GitHub Actions integration
- reusable organizational test policies
- DNS propagation comparison
- multiple DNS resolver comparison
- RBL/DNSBL querying
- reputation provider adapters
- BIMI inspection
- S/MIME inspection
- OpenPGP/MIME inspection
- RFC conformance suites
- bounce/DSN analyzer
- feedback-loop header inspection
- SMTP load testing with strict safety controls
- message mutation testing
- webhook sink
- local SMTP sink
- temporary built-in test sink

---

# 60. Potential Killer Feature: Test Recipes

Mailbench should eventually introduce **Recipes**.

A recipe is a reusable diagnostic workflow.

Example:

```text
Outbound Implementation Validation

✓ PTR
✓ Forward DNS
✓ SPF authorization
✓ DKIM DNS
✓ SMTP connectivity
✓ STARTTLS
✓ Send test
✓ Sink receipt
✓ DKIM signature
✓ DMARC alignment

```

Another:

```text
"Why isn't mail leaving?"

1. DNS resolution
2. MX discovery
3. MX connectivity
4. STARTTLS negotiation
5. SMTP transaction
6. Response analysis

```

Another:

```text
"Customer says DKIM is broken"

1. Discover selector
2. Retrieve key
3. Validate key
4. Send message
5. Retrieve sink copy
6. Verify signature
7. Compare canonicalized body
8. Inspect Authentication-Results

```

This creates a bridge between individual tools and actual implementation/support workflows.

---

# 61. UX Philosophy

Mailbench should not merely say:

```text
DKIM FAIL

```

It should answer three questions:

```text
WHAT HAPPENED?

WHY?

WHAT SHOULD I CHECK NEXT?

```

Example:

```text
DKIM                              FAIL

The delivered message contains:

d=example.com
s=halon

The selector resolves successfully, but the DKIM body hash
does not match the received body.

DNS                              PASS
Public key                       PASS
Body hash                        FAIL
Signature                        NOT VERIFIED

Likely investigation areas:

• Message modification after signing
• MIME transformation
• Footer insertion
• Content encoding changes
• Incorrect signing stage

[View Signature] [Compare Body] [View Raw Message]

```

Mailbench should guide investigation without pretending to know configuration it cannot observe.

---

# 62. Performance Requirements

Typical individual DNS checks:

**Target:** <500 ms excluding external network delays.

Full environment scan:

**Target:** <5 seconds where remote systems respond normally.

Independent tests should run concurrently where safe.

Example:

```text
            ┌── SPF
DNS ────────├── DKIM
            ├── DMARC
            ├── MX
            └── PTR

```

Do not serialize unrelated DNS requests unnecessarily.

---

# 63. Reliability Requirements

- Network failures must never crash the application.
- Malformed DNS responses must produce structured errors.
- Malformed messages must remain inspectable.
- SMTP timeouts must be configurable.
- IPv4 and IPv6 failures must be distinguishable.
- Individual failed tests must not terminate an entire suite unless required.
- All network operations must have timeouts.
- Canceling a GUI test must cleanly cancel active operations.

---

# 64. Testing Strategy

The Mailbench project itself requires extensive tests.

Include:

### Unit tests

- DNS parsing
- SPF evaluation
- DKIM canonicalization
- DKIM verification
- DMARC alignment
- SMTP response parsing
- MIME parsing
- Authentication-Results parsing

### Integration tests

Use containerized/local test infrastructure where practical.

Test:

- SMTP success
- SMTP rejection
- STARTTLS
- broken TLS
- malformed DKIM
- SPF recursion
- SPF lookup limit
- DMARC alignment
- IPv4
- IPv6
- timeout behavior

Golden `.eml` fixtures should cover known authentication scenarios.

---

# 65. CLI UX Requirements

CLI output must look excellent in both interactive and automated environments.

Interactive:

```text
✓ SPF     PASS
✓ DKIM    PASS
✗ DMARC   FAIL

```

No-color mode:

```bash
NO_COLOR=1 mailbench check example.com

```

Support:

```bash
--no-color
--json
--quiet
--verbose

```

Respect standard terminal conventions.

---

# 66. Accessibility

macOS requirements:

- VoiceOver-compatible controls
- keyboard navigation
- sufficient contrast
- status not communicated solely through color
- Dynamic Type / scalable text where appropriate
- Reduce Motion support

---

# 67. Success Criteria

Mailbench succeeds when an implementation/support engineer can begin with:

```bash
mailbench check customer.example

```

and obtain enough information to identify most common email infrastructure configuration problems without manually switching among numerous utilities.

The GUI succeeds when the same engineer can perform deeper investigation without sacrificing the raw technical information available from the CLI.

The ultimate workflow should become:

```text
Configure
    ↓
Mailbench
    ↓
Fix
    ↓
Mailbench
    ↓
PASS

```

rather than:

```text
dig
↓
swaks
↓
openssl
↓
dig again
↓
Google an SPF parser
↓
open message source
↓
grep headers
↓
send another message
↓
where did I put that command?

```

---

# 68. Definition of Done for Initial Release

Mailbench v1 is ready when an engineer can:

1. Create a profile for an implementation.
2. Run a complete domain/environment assessment.
3. Inspect MX, PTR, SPF, DKIM, and DMARC.
4. Test SMTP connectivity and capabilities.
5. Validate STARTTLS and certificates.
6. Build and send a test message.
7. use Swaks when exact Swaks behavior is desirable.
8. inspect the complete SMTP conversation.
9. analyze a received `.eml`.
10. independently verify DKIM and DMARC.
11. save test history.
12. rerun the same validation later.
13. compare results.
14. export a technical report.
15. perform all essential operations from either CLI or macOS.
16. access raw diagnostic evidence behind every interpreted result.

The result should feel less like a collection of email utilities and more like an **integrated diagnostic environment for email infrastructure**.