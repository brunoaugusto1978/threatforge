# Security Policy

## Supported Versions

ThreatForge is currently in early-stage development. Security fixes will be applied to the latest version available on the `main` branch and to the latest tagged release when applicable.

| Version | Supported |
| ------- | --------- |
| 0.6.x   | Yes       |
| < 0.6   | No        |

## Reporting a Vulnerability

If you believe you have found a security vulnerability in ThreatForge, please report it responsibly.

Do not open a public GitHub issue for sensitive vulnerabilities.

Preferred contact:

Open a private GitHub Security Advisory or contact the maintainer directly.

When reporting, include:

- affected version or commit;
- affected file and function, if known;
- steps to reproduce;
- expected impact;
- proof of concept, if safe to share;
- suggested remediation, if available.

## Scope

The following areas are considered in scope:

- authentication and session management;
- tenant isolation and authorization;
- API key handling;
- invitation token flow;
- audit logging;
- secrets handling;
- SSRF, injection, XSS, CSRF and other OWASP Top 10 classes;
- Docker and deployment defaults;
- dependency vulnerabilities;
- data exposure across tenants.

## Out of Scope

The following are out of scope unless they lead to a concrete security impact:

- denial-of-service against local development environments;
- reports requiring physical access to the host;
- vulnerabilities caused by intentionally insecure local configuration;
- social engineering;
- spam or automated scanner output without validation;
- issues affecting third-party services not controlled by this project.

## Responsible Testing

Do not use ThreatForge to attack third-party systems without authorization.

Do not submit real credentials, private tokens, leaked personal data, stolen data or production secrets as test evidence.

Use local labs, synthetic indicators and controlled environments.

## Security Expectations for Production

Before production usage, operators must review and configure:

- strong API_KEY;
- strong JWT_SECRET;
- secure POSTGRES_PASSWORD;
- HTTPS termination;
- COOKIE_SECURE=true;
- restricted CORS_ORIGINS;
- SMTP configuration;
- log retention and token redaction;
- backup and restore process;
- dependency scanning;
- container and host hardening.

## Disclosure Process

After receiving a valid vulnerability report, the maintainer will attempt to:

1. acknowledge the report;
2. validate the issue;
3. classify severity;
4. prepare a fix;
5. publish a security note or release when appropriate.

ThreatForge is an open source defensive security project. Coordinated disclosure is expected.
