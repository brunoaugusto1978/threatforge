# ThreatForge Community Roadmap

This roadmap lists planned future work for ThreatForge Community.

Completed open source readiness work is not listed as future roadmap work. It is tracked in the public readiness documentation.

See:

- `docs/PUBLIC_READINESS_CHECK.md`
- `PRODUCT_STRATEGY.md`
- `docs/ENTERPRISE_ADAPTER.md`

## Current Baseline

ThreatForge Community currently includes:

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
- baseline security hardening;
- optional Enterprise adapter;
- public readiness validation.

## v0.7 — Investigation Cases

Goal: introduce structured investigation workflows.

Planned work:

- case model;
- case creation and listing;
- case detail view;
- analyst notes;
- evidence attachments;
- case status workflow;
- case-level export;
- audit events for case operations.

Suggested contribution areas:

- backend API;
- frontend UI;
- documentation;
- tests;
- export formats.

## v0.8 — Timeline and Operational Review

Goal: improve investigation traceability and reporting.

Planned work:

- investigation timeline;
- activity history;
- analyst action tracking;
- operational review workflow;
- report export improvements;
- case summary export;
- review notes;
- evidence chronology.

Suggested contribution areas:

- timeline UI;
- backend event model;
- export generation;
- analyst workflow design;
- testing.

## v0.9 — Relationship Graph

Goal: support entity correlation and graph-based investigation.

Planned work:

- relationship graph model;
- Neo4j integration;
- entity correlation views;
- observable-to-brand relationships;
- domain/IP/URL relationship mapping;
- graph export;
- graph query examples.

Suggested contribution areas:

- Neo4j setup;
- graph schema;
- frontend visualization;
- correlation logic;
- documentation.

## v1.0 — Stable Community Release

Goal: deliver a stable public release baseline.

Planned work:

- partial STIX model;
- MISP integration;
- OpenCTI integration;
- production hardening review;
- stable packaging;
- deployment documentation;
- upgrade notes;
- public stable release checklist.

Suggested contribution areas:

- CTI standards;
- integrations;
- deployment hardening;
- documentation;
- release engineering.

## Enterprise Boundary

ThreatForge Community may include public adapters, documentation and extension points.

Premium Enterprise implementation code must remain in the private `threatforge-enterprise` repository.
