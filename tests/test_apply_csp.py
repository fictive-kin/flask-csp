"""
tests.test_apply_csp
"""

from flask import Blueprint

from flask_csp import CSP, apply_csp, csp


def test_apply_csp_adds_the_app_policy_early(base_app):
    """The policy can be read before the extension's after_request runs."""

    seen = {}
    CSP(base_app, img_src="data:")

    # Registered after the extension, so it runs before the extension's after_request.
    @base_app.after_request
    def inspect(response):
        seen["before"] = response.headers.get("Content-Security-Policy")
        seen["applied"] = apply_csp(response).headers.get("Content-Security-Policy")
        return response

    with base_app.test_client() as c:
        rv = c.get("/undecorated")

    assert seen["before"] is None
    assert seen["applied"] == "default-src 'self'; img-src data:"
    # Not added a second time.
    assert rv.headers.getlist("Content-Security-Policy") == [seen["applied"]]


def test_apply_csp_leaves_a_decorated_response_alone(base_app):
    CSP(base_app)

    @base_app.route("/decorated")
    @csp(img_src="data:")
    def decorated():
        response = base_app.make_response("hi")
        return response

    @base_app.after_request
    def reapply(response):
        return apply_csp(response)

    with base_app.test_client() as c:
        rv = c.get("/decorated")

    assert rv.headers.getlist("Content-Security-Policy") == [
        "default-src 'self'; img-src data:"
    ]


def test_apply_csp_prefers_the_blueprint_policy(base_app):
    CSP(base_app)
    bp = Blueprint("bp", __name__)

    @bp.route("/bp")
    def view():
        response = base_app.make_response("hi")
        return apply_csp(response)

    CSP().init_blueprint(bp, default_src="none")
    base_app.register_blueprint(bp)

    with base_app.test_client() as c:
        rv = c.get("/bp")

    assert rv.headers.getlist("Content-Security-Policy") == ["default-src 'none'"]


def test_apply_csp_without_a_policy(base_app):
    @base_app.route("/plain")
    def plain():
        return apply_csp(base_app.make_response("hi"))

    with base_app.test_client() as c:
        rv = c.get("/plain")

    assert rv.headers.get("Content-Security-Policy") is None
