"""
tests.test_blueprint_extension
"""


from flask import Blueprint, url_for

from flask_csp import CSP


def report(app):
    report_bp = Blueprint('report-only', __name__)

    @report_bp.route('/test')
    def report_only():
        return 'Blueprint-only report-only', 200

    report_csp = CSP()
    report_csp.init_blueprint(report_bp, report_only=True, report_uri='https://example.com/csp/receiver')
    app.register_blueprint(report_bp, prefix='/report-only-bp')

    return report_bp


def full(app):
    full_bp = Blueprint('full-csp', __name__)

    @full_bp.route('/other-test')
    def full():
        return 'Blueprint-only fully active', 200

    full_csp = CSP()
    full_csp.init_blueprint(full_bp, report_uri='https://example.com/csp/receiver')
    app.register_blueprint(full_bp, prefix='/full-bp')

    return full_bp


def test_blueprint(base_app):
    """Ensure that the simple CSP extension adds the after request processor only to the blueprint's routes"""

    report(base_app)
    full(base_app)

    csp_header = "default-src 'self'; report-uri https://example.com/csp/receiver"

    with base_app.app_context(), base_app.test_client() as c:
        rv = c.get(url_for('report-only.report_only'))  # '/report-only-bp/test')
        assert rv.status_code == 200
        assert rv.headers.get('Content-Security-Policy') == None
        assert rv.headers.get('Content-Security-Policy-Report-Only') == csp_header

        rv = c.get(url_for('full-csp.full'))  # '/full-bp/test')
        assert rv.status_code == 200
        assert rv.headers.get('Content-Security-Policy') == csp_header
        assert rv.headers.get('Content-Security-Policy-Report-Only') == None

        rv = c.get('/undecorated')
        assert rv.status_code == 200
        assert rv.headers.get('Content-Security-Policy') == None
        assert rv.headers.get('Content-Security-Policy-Report-Only') == None
