# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.x     | Yes       |
| 1.x     | No        |

## Reporting a vulnerability

Please **do not open a public issue** for a suspected vulnerability.

Use GitHub's private vulnerability reporting / Security Advisory feature for
this repository. Include:

- affected Nepticon version and operating system;
- whether the issue affects the server, the agent, or both;
- reproduction steps and a minimal proof of concept;
- the security impact you believe it has.

You can expect an initial acknowledgement, a triage decision and a coordinated
disclosure timeline. Please allow time for a fix before publishing details.

## Scope reminders

- Nepticon executes commands with the agent's operating-system privileges.
  Running it against systems without authorization is out of scope and
  prohibited.
- The generated CA and certificates are intended for lab/internal use; report
  issues in the certificate generator separately from PKI misconfiguration.
- The local audit log is tamper-evident, not tamper-proof against an attacker
  who already has root on the server.
