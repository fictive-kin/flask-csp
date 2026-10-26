"""
tests.test_policy
"""

import pytest

from flask_csp.constants import (
    Directive,
    FetchRestriction,
    SandboxRestriction,
    TrustedTypesRestriction,
)
from flask_csp.policy import (
    BaseDirective,
    ContentSecurityPolicy,
    EmptyDirective,
    Header,
    ReportGroup,
    ReportOnlyPolicy,
    ReportTo,
    SandboxDirective,
    SimpleDirective,
    SourceDirective,
    TrustedTypesDirective,
    is_allowed_directive,
    is_allowed_fetch_restriction,
    is_allowed_sandbox_restriction,
    is_allowed_trustedtype_restriction,
    load_directive,
)


def test_allowed_items():
    """Ensure that the allowed items determination code works"""

    for directive in Directive:
        assert is_allowed_directive(directive) == directive
        assert is_allowed_directive(directive.name) == directive
        assert is_allowed_directive(directive.value) == directive

    for restriction in FetchRestriction:
        assert is_allowed_fetch_restriction(restriction) == restriction
        assert is_allowed_fetch_restriction(restriction.name) == restriction
        assert is_allowed_fetch_restriction(restriction.value) == restriction

    for restriction in SandboxRestriction:
        assert is_allowed_sandbox_restriction(restriction) == restriction
        assert is_allowed_sandbox_restriction(restriction.name) == restriction
        assert is_allowed_sandbox_restriction(restriction.value) == restriction

    for restriction in TrustedTypesRestriction:
        assert is_allowed_trustedtype_restriction(restriction) == restriction
        assert is_allowed_trustedtype_restriction(restriction.name) == restriction
        assert is_allowed_trustedtype_restriction(restriction.value) == restriction

    with pytest.raises(ValueError):
        is_allowed_directive("non-existent")
    with pytest.raises(ValueError):
        is_allowed_fetch_restriction("non-existent")
    with pytest.raises(ValueError):
        is_allowed_sandbox_restriction("non-existent")
    with pytest.raises(ValueError):
        is_allowed_trustedtype_restriction("non-existent")


@pytest.mark.parametrize(
    "directive, result",
    [
        (
            Directive.STYLE_SRC,
            SourceDirective,
        ),
        (
            Directive.SCRIPT_SRC,
            SourceDirective,
        ),
        (
            Directive.DEFAULT_SRC,
            SourceDirective,
        ),
        (
            Directive.SANDBOX,
            SandboxDirective,
        ),
        (
            Directive.UPGRADE_INSECURE_REQUESTS,
            EmptyDirective,
        ),
        (
            Directive.REPORT_URI,
            SimpleDirective,
        ),
        (
            Directive.TRUSTED_TYPES,
            TrustedTypesDirective,
        ),
    ],
)
def test_load_directive(directive, result):
    """Ensure that load directive returns the correct types"""

    policy_directive = load_directive(directive)
    assert policy_directive.directive == directive
    assert isinstance(policy_directive, result)


@pytest.mark.parametrize(
    "directive",
    [
        "non-extistent",
        "ugrade-insecure-requests",
        "APPLE_DUMPLING_GANG",
        "Weird ch@racter",
    ],
)
def test_load_directive_fails(directive):
    """Ensure that load directive fails appropriately"""

    with pytest.raises(ValueError):
        load_directive(directive)


@pytest.mark.parametrize(
    "invalid",
    [
        lambda: BaseDirective(Directive.DEFAULT_SRC, ""),
        lambda: EmptyDirective(Directive.DEFAULT_SRC),
        lambda: EmptyDirective(Directive.UPGRADE_INSECURE_REQUESTS).add("value"),
        lambda: SimpleDirective(Directive.REPORT_URI, ""),
        lambda: SimpleDirective(Directive.REPORT_URI, FetchRestriction.SELF),
        lambda: SimpleDirective(
            Directive.REPORT_URI, "https://a.example.com", "https://b.example.com"
        ),
        lambda: SandboxDirective(""),
        lambda: SandboxDirective("allow-everything"),
        lambda: TrustedTypesDirective(""),
        lambda: SourceDirective(Directive.DEFAULT_SRC, ""),
        lambda: ReportTo("not-a-group"),
        lambda: ContentSecurityPolicy("not-a-directive"),
    ],
)
def test_invalid_policy_values(invalid):
    """Ensure that invalid directives, restrictions and headers are rejected"""

    with pytest.raises(ValueError):
        invalid()


def test_header():
    """Ensure header throws not implemented correctly"""

    header = Header()

    with pytest.raises(NotImplementedError):
        header.key
    with pytest.raises(NotImplementedError):
        header.value


@pytest.mark.parametrize(
    "groups, result",
    [
        (
            ReportGroup("single-endpoint", "https://example.com/csp/receiver"),
            '{"endpoints": [{"url": "https://example.com/csp/receiver"}], "group": "single-endpoint", "max_age": 3600}',
        ),
        (
            ReportGroup(
                "multiple-endpoints",
                [
                    "https://example.com/csp/receiver",
                    "https://example.com/csp/other-receiver",
                ],
            ),
            '{"endpoints": [{"url": "https://example.com/csp/receiver"}, {"url": "https://example.com/csp/other-receiver"}], "group": "multiple-endpoints", "max_age": 3600}',
        ),
        (
            ReportGroup(
                "single-endpoint-max-age",
                "https://example.com/csp/receiver",
                max_age=60,
            ),
            '{"endpoints": [{"url": "https://example.com/csp/receiver"}], "group": "single-endpoint-max-age", "max_age": 60}',
        ),
        (
            [ReportGroup("no-endpoints", None), None],
            '{"endpoints": [], "group": "no-endpoints", "max_age": 3600}',
        ),
    ],
)
def test_report_to(groups, result):
    """Ensure ReportTo outputs correctly"""

    report_to = ReportTo(groups)

    assert str(report_to) == f"Report-To: {result}"


@pytest.mark.parametrize(
    "csp_directives, result",
    [
        (
            EmptyDirective(Directive.UPGRADE_INSECURE_REQUESTS),
            "upgrade-insecure-requests",
        ),
        (
            SourceDirective(Directive.DEFAULT_SRC, FetchRestriction.UNSAFE_INLINE),
            "default-src 'unsafe-inline'",
        ),
        (
            [
                EmptyDirective(Directive.UPGRADE_INSECURE_REQUESTS),
                SourceDirective(Directive.DEFAULT_SRC, FetchRestriction.UNSAFE_INLINE),
                SourceDirective(Directive.STYLE_SRC, FetchRestriction.SELF),
            ],
            "upgrade-insecure-requests; default-src 'unsafe-inline'; style-src 'self'",
        ),
        (
            [
                EmptyDirective(Directive.UPGRADE_INSECURE_REQUESTS),
                SimpleDirective(
                    Directive.REPORT_URI, "https://example.com/csp/receiver"
                ),
            ],
            "upgrade-insecure-requests; report-uri https://example.com/csp/receiver",
        ),
        (
            [
                SandboxDirective(SandboxRestriction.ALLOW_SCRIPTS, "allow-forms"),
                TrustedTypesDirective(
                    "my-policy", TrustedTypesRestriction.ALLOW_DUPLICATES
                ),
                load_directive(SourceDirective(Directive.IMG_SRC, "data:")),
            ],
            "sandbox allow-scripts allow-forms; trusted-types my-policy 'allow-duplicates'; img-src data:",
        ),
    ],
)
def test_csp(csp_directives, result):
    """Ensure that the CSP header is returned correctly"""

    csp = ContentSecurityPolicy(csp_directives)

    assert str(csp) == f"Content-Security-Policy: {result}"


@pytest.mark.parametrize(
    "csp_directives, result",
    [
        (
            [
                EmptyDirective(Directive.UPGRADE_INSECURE_REQUESTS),
                SourceDirective(Directive.DEFAULT_SRC, FetchRestriction.UNSAFE_INLINE),
                SourceDirective(Directive.STYLE_SRC, FetchRestriction.SELF),
                SimpleDirective(
                    Directive.REPORT_URI, "https://example.com/csp/receiver"
                ),
            ],
            "upgrade-insecure-requests; default-src 'unsafe-inline'; style-src 'self'; report-uri https://example.com/csp/receiver",
        ),
        (
            [
                EmptyDirective(Directive.UPGRADE_INSECURE_REQUESTS),
                SimpleDirective(
                    Directive.REPORT_URI, "https://example.com/csp/receiver"
                ),
            ],
            "upgrade-insecure-requests; report-uri https://example.com/csp/receiver",
        ),
    ],
)
def test_report_only_csp(csp_directives, result):
    """Ensure that the Report Only CSP header is returned correctly"""

    csp = ReportOnlyPolicy(csp_directives)

    assert str(csp) == f"Content-Security-Policy-Report-Only: {result}"


def test_report_only_csp_fail():

    csp = ReportOnlyPolicy(
        SourceDirective(Directive.DEFAULT_SRC, FetchRestriction.UNSAFE_INLINE),
    )

    with pytest.raises(ValueError):
        csp.value
