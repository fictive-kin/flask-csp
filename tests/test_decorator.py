"""
tests.test_decorator
"""

import pytest


@pytest.mark.parametrize(
    "test_app, csp_state, csp_report_state",
    [
        (
            "decorated_app",
            True,
            False,
        ),
    ],
)
def test_decorator(request, test_app, csp_state, csp_report_state):
    """Ensure that the CSP decorator adds the CSP header"""

    test_app = request.getfixturevalue(test_app)

    with test_app.app_context(), test_app.test_client() as c:
        rv = c.get("/undecorated")
        assert bool(rv.headers.get("Content-Security-Policy")) == False
        assert bool(rv.headers.get("Content-Security-Policy-Report-Only")) == False

        rv = c.get("/decorated")
        assert bool(rv.headers.get("Content-Security-Policy")) == csp_state
        assert (
            bool(rv.headers.get("Content-Security-Policy-Report-Only"))
            == csp_report_state
        )
        assert "default-src" in rv.headers.get("Content-Security-Policy")
        assert "style-src" not in rv.headers.get("Content-Security-Policy")

        rv = c.get("/decorated/style-src")
        assert bool(rv.headers.get("Content-Security-Policy")) == csp_state
        assert (
            bool(rv.headers.get("Content-Security-Policy-Report-Only"))
            == csp_report_state
        )
        assert "default-src" in rv.headers.get("Content-Security-Policy")
        assert "style-src" in rv.headers.get("Content-Security-Policy")


@pytest.mark.parametrize(
    "test_app, csp_state, csp_report_state",
    [
        (
            "decorated_app",
            False,
            True,
        ),
    ],
)
def test_decorator_report_only(request, test_app, csp_state, csp_report_state):
    """Ensure that the CSP decorator adds the CSP header for report only"""

    test_app = request.getfixturevalue(test_app)

    with test_app.app_context(), test_app.test_client() as c:
        rv = c.get("/undecorated")
        assert bool(rv.headers.get("Content-Security-Policy")) == False
        assert bool(rv.headers.get("Content-Security-Policy-Report-Only")) == False

        rv = c.get("/decorated/report-only")
        assert bool(rv.headers.get("Content-Security-Policy")) == csp_state
        assert (
            bool(rv.headers.get("Content-Security-Policy-Report-Only"))
            == csp_report_state
        )
        assert "default-src" in rv.headers.get("Content-Security-Policy-Report-Only")
        assert "report-uri" in rv.headers.get("Content-Security-Policy-Report-Only")
