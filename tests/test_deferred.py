"""
tests.test_deferred

Callable option values are worked out for each response, from the value they replace.
"""

from flask import request

from flask_csp import CSP, csp, standalone_csp


def test_decorator_callable_extends_the_app_setting(base_app):
    base_app.config["CSP_FRAME_SRC"] = ["self"]

    @base_app.route("/framed")
    @csp(frame_src=lambda current: [*current, request.args["host"]])
    def framed():
        return "hi"

    with base_app.test_client() as c:
        one = c.get("/framed?host=https://one.example.com")
        two = c.get("/framed?host=https://two.example.com")

    assert one.headers["Content-Security-Policy"] == (
        "default-src 'self'; frame-src 'self' https://one.example.com"
    )
    assert (
        "frame-src 'self' https://two.example.com"
        in two.headers["Content-Security-Policy"]
    )


def test_decorator_callable_gets_none_without_a_setting(base_app):
    seen = []

    @base_app.route("/framed")
    @csp(frame_src=lambda current: seen.append(current) or "https://example.com")
    def framed():
        return "hi"

    with base_app.test_client() as c:
        rv = c.get("/framed")

    assert seen == [None]
    assert "frame-src https://example.com" in rv.headers["Content-Security-Policy"]


def test_callable_returning_nothing_leaves_the_directive_out(base_app):
    @base_app.route("/framed")
    @csp(frame_src=lambda current: None)
    def framed():
        return "hi"

    with base_app.test_client() as c:
        rv = c.get("/framed")

    assert rv.headers["Content-Security-Policy"] == "default-src 'self'"


def test_standalone_callable(base_app):
    base_app.config["CSP_FRAME_SRC"] = ["self"]  # not used by standalone_csp

    @base_app.route("/standalone")
    @standalone_csp(
        default_src="none", frame_src=lambda current: current or "https://example.com"
    )
    def standalone():
        return "hi"

    with base_app.test_client() as c:
        rv = c.get("/standalone")

    assert rv.headers["Content-Security-Policy"] == (
        "default-src 'none'; frame-src https://example.com"
    )


def test_extension_callable(base_app):
    base_app.config["CSP_IMG_SRC"] = ["self"]
    CSP(base_app, img_src=lambda current: [*current, request.host])

    with base_app.test_client() as c:
        rv = c.get("/undecorated")

    assert rv.headers["Content-Security-Policy"] == (
        "default-src 'self'; img-src 'self' localhost:5000"
    )
