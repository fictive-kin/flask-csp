"""
tests.conftest
"""

import os

import pytest
from flask import Flask

from flask_csp import CSP, csp
from flask_csp.constants import FetchRestriction


@pytest.fixture()
def base_app():
    """
    Create a Flask app context for the tests without the CSP extension.
    """

    os.environ['FLASK_ENV'] = 'testing'
    app = Flask('testing')
    app.config['SERVER_NAME'] = 'localhost:5000'

    @app.route('/undecorated')
    def undecorated():
        return 'Should only have the CSP header when CSP extension is active', 200

    yield app


@pytest.fixture()
def app(base_app):
    """
    Creates a Flask app for the tests with the CSP extension
    """

    CSP(base_app)

    @base_app.route('/extension/decorated/report-only')
    @csp(
        report_only=True,
        report_uri='https://example.com/csp/receiver',
        default_src=FetchRestriction.SELF,
    )
    def decorated_report_only():
        return 'Some decorated route while extension is active', 200

    yield base_app


@pytest.fixture()
def receiver_app(base_app):
    """
    Creates a Flask app for the tests with the CSP extension and simple receiver
    """

    @base_app.route('/extension/decorated/report-only')
    @csp(
        report_only=True,
        report_uri='https://example.com/csp/receiver',
        default_src=FetchRestriction.SELF,
    )
    def decorated_report_only():
        return 'Some decorated route while extension is active', 200

    CSP(base_app, receiver_prefix='/csp')
    yield base_app


@pytest.fixture()
def report_only_app(base_app):
    """
    Creates a Flask app for the tests with the CSP extension and simple receiver
    """

    @base_app.route('/report-only/extension/decorated')
    @csp(report_only=False)
    def decorated_non_report():
        return 'Should return regular CSP header, not report-only one', 200

    CSP(base_app, receiver_prefix='/csp', report_only=True, report_uri='https://example.com/report/receiver')
    yield base_app


@pytest.fixture()
def minimal_csp_report():
    """
    A simple CSP report
    """

    return {
        "csp-report": {
            "document-uri": "http://example.com/signup.html",
            "blocked-uri": "http://example.com/css/style.css",
            "violated-directive": "style-src cdn.example.com",
            "original-policy":
                "default-src 'none'; style-src cdn.example.com; report-uri /_/csp-reports",
            "disposition": "report"
        }
    }


@pytest.fixture()
def full_csp_report(minimal_csp_report):
    """
    A CSP report with most keys set
    """

    minimal_csp_report.update({
        "effective-directive": "style-src",
        "referrer": "",
        "line-number": 8,
        "source-file": "http://example.com/css/style.css",
        "status-code": 0,
        "script-sample": ".somthing { height: 100% }",
    })
    return minimal_csp_report


@pytest.fixture
def decorated_app(base_app):
    """
    A simple Flask app with a CSP decorated route
    """

    @base_app.route('/decorated')
    @csp
    def decorated_route():
        return 'Some decorated route', 200

    @base_app.route('/decorated/report-only')
    @csp(
        report_only=True,
        report_uri='https://example.com/csp/receiver',
        default_src=FetchRestriction.SELF,
    )
    def decorated_report_only():
        return 'Some decorated route', 200

    @base_app.route('/decorated/style-src')
    @csp(
        style_src=[FetchRestriction.SELF, FetchRestriction.UNSAFE_INLINE, '*.example.com'],
        upgrade_insecure_requests=True,
        report_uri='https://example.com/csp/receiver',
    )
    def style_src_decorated():
        return 'Should include style-src CSP rule', 200

    yield base_app
