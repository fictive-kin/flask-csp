"""
tests.test_decorator
"""

import pytest

from flask_csp import CSP, standalone_csp


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


@pytest.fixture
def standalone_app(base_app):
    """An app with app-wide CSP settings, the extension and standalone views"""

    base_app.config["CSP_STYLE_SRC"] = ["self"]
    base_app.config["CSP_FRAME_ANCESTORS"] = ["self"]
    CSP(base_app)

    @base_app.route("/standalone")
    @standalone_csp(sandbox=True, default_src="none")
    def standalone_route():
        return "Sandboxed", 200

    @standalone_csp(
        sandbox=["allow-scripts"],
        script_src="self",
        report_only=True,
        report_uri="https://example.com/csp/receiver",
    )
    def render_widget():
        return "Not a view itself"

    @base_app.route("/standalone/helper")
    def via_helper():
        return render_widget()

    yield base_app


def test_standalone_decorator(standalone_app):
    """Only the standalone policy is sent, without the app's settings or defaults"""

    with standalone_app.test_client() as c:
        rv = c.get("/undecorated")
        assert rv.headers.getlist("Content-Security-Policy") == [
            "default-src 'self'; style-src 'self'; frame-ancestors 'self'"
        ]

        rv = c.get("/standalone")
        assert rv.headers.getlist("Content-Security-Policy") == [
            "sandbox; default-src 'none'"
        ]


def test_standalone_decorator_on_helper(standalone_app):
    """Any function returning a response can be wrapped, and options apply"""

    with standalone_app.test_client() as c:
        rv = c.get("/standalone/helper")
        assert rv.headers.getlist("Content-Security-Policy") == []
        assert rv.headers["Content-Security-Policy-Report-Only"] == (
            "sandbox allow-scripts; script-src 'self'; "
            "report-uri https://example.com/csp/receiver"
        )


def test_standalone_decorator_needs_directives():
    with pytest.raises(TypeError):
        standalone_csp()
