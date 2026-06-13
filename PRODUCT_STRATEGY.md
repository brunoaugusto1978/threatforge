# ThreatForge Product Strategy

ThreatForge will have two editions:

## ThreatForge Community Edition

The Community Edition will be the open source version of ThreatForge.

It will live in the public repository:

threatforge

It should include the open source CTI and Digital Risk Protection core:

- multi-tenant architecture;
- tenant isolation;
- users and roles;
- platform operators;
- support operators;
- invitation-based onboarding;
- CTI observable intake;
- public-source enrichment;
- brand monitoring;
- explainable scoring;
- Markdown reports;
- Docker deployment;
- CI selftest;
- baseline security hardening.

## ThreatForge Enterprise Edition

The Enterprise Edition will be the commercial/private version of ThreatForge.

It should live in a separate private repository:

threatforge-enterprise

It should include commercial features such as:

- signed license validation;
- 90-day trial;
- license-based feature flags;
- premium PDF reports;
- executive dashboards;
- advanced connectors;
- enterprise integrations;
- advanced audit exports;
- tenant/user limits by license;
- commercial support workflows.

## Repository Rule

Premium Enterprise implementation code must not be placed inside the public Community repository.

The public repository may contain documentation, interfaces or stubs, but the real Enterprise implementation should stay in the private repository.

## Next Steps

1. Keep threatforge as the Community Edition.
2. Create a private repository named threatforge-enterprise.
3. Define the signed license model.
4. Implement trial mode in the Enterprise repository.
5. Implement premium PDF reports in the Enterprise repository.
