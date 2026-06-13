# Optional Enterprise Adapter

ThreatForge Community can optionally integrate with ThreatForge Enterprise when the private Enterprise package is installed.

The Community repository must not contain Enterprise implementation code.

## Behavior

When threatforge-enterprise is not installed:

- Community continues working normally.
- Enterprise features are reported as unavailable.
- Enterprise feature checks return false.
- Premium report generation raises an EnterpriseUnavailableError.

When threatforge-enterprise is installed:

- Community can query Enterprise license status.
- Community can check Enterprise feature availability.
- Community can call premium PDF generation through the private Enterprise integration contract.

## Public Adapter

The Community adapter lives in:

    app/enterprise_adapter.py

Main functions:

    enterprise_available()
    get_enterprise_status()
    is_enterprise_feature_enabled(feature)
    generate_enterprise_pdf_report(report, output_path)

## Security Boundary

Premium implementation code must remain in the private Enterprise repository.

The Community repository may only contain optional adapter code, public stubs and documentation.
