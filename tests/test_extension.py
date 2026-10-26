"""
tests.test_extension
"""

import pytest

from flask_csp import CSP


@pytest.mark.parametrize('test_app, state', [
    ('base_app', False,),
    ('app', True,),
    ('receiver_app', True,),
])
def test_after_request_added(request, test_app, state):
    """Ensure that the simple CSP extension adds the after request processor"""

    test_app = request.getfixturevalue(test_app)

    after_request_found = False
    for v in test_app.after_request_funcs.values():
        for i in v:
            if i.__qualname__ == 'CSP.after_request':
                after_request_found = True
                break

    assert after_request_found == state


@pytest.mark.parametrize('test_app, state', [
    ('base_app', False,),
    ('app', False,),
    ('receiver_app', True,),
])
def test_receiver_route_added(request, test_app, state):
    """Ensure that the receiver blueprint does not get added when no prefix is provided"""

    test_app = request.getfixturevalue(test_app)

    receiver_route_found = False
    for rule in test_app.url_map.iter_rules():
        if rule.rule == '/csp/report':
            receiver_route_found = True
            break

    assert receiver_route_found == state


@pytest.mark.parametrize('intercept_exceptions', [True, False])
def test_extension_intercept_exceptions(base_app, intercept_exceptions):
    """Ensure that intercept_exceptions is not treated as a CSP directive"""

    CSP(base_app, intercept_exceptions=intercept_exceptions)

    with base_app.test_client() as c:
        rv = c.get('/undecorated')
        assert rv.status_code == 200
        assert rv.headers.get('Content-Security-Policy') == "default-src 'self'"


def test_extension_rejects_invalid_targets(base_app):
    """Ensure that the extension can only be initialized on apps and blueprints"""

    with pytest.raises(ValueError):
        CSP().init_app(object())
    with pytest.raises(ValueError):
        CSP().init_blueprint(base_app)


def test_extension_report_only_from_config(base_app):
    """Ensure that report_only can be set via the app config, like the directives"""

    base_app.config['CSP_REPORT_ONLY'] = True
    base_app.config['CSP_REPORT_URI'] = 'https://example.com/report/receiver'
    CSP(base_app)

    with base_app.test_client() as c:
        rv = c.get('/undecorated')
        assert rv.headers.get('Content-Security-Policy') is None
        assert rv.headers.get('Content-Security-Policy-Report-Only') == (
            "default-src 'self'; report-uri https://example.com/report/receiver"
        )


def test_extension_report_only_kwarg_overrides_config(base_app):
    """Ensure that the extension kwargs take precedence over the app config for report_only"""

    base_app.config['CSP_REPORT_ONLY'] = True
    CSP(base_app, report_only=False)

    with base_app.test_client() as c:
        rv = c.get('/undecorated')
        assert rv.headers.get('Content-Security-Policy') == "default-src 'self'"
        assert rv.headers.get('Content-Security-Policy-Report-Only') is None


@pytest.mark.parametrize('test_app, route, csp_state, csp_report_state', [
    ('app', '/undecorated', "default-src 'self'", None,),
    ('receiver_app', '/undecorated', "default-src 'self'", None,),
    ('report_only_app', '/undecorated', None, "default-src 'self'; report-uri https://example.com/report/receiver",),
    ('app', '/extension/decorated/report-only', None, "default-src 'self'; report-uri https://example.com/csp/receiver",),
    ('receiver_app', '/extension/decorated/report-only', None, "default-src 'self'; report-uri https://example.com/csp/receiver",),
    ('report_only_app', '/report-only/extension/decorated', "default-src 'self'", None,),
])
def test_extension_csp_header(request, test_app, route, csp_state, csp_report_state):
    """Ensure that the CSP extension adds the CSP header appropriately"""

    test_app = request.getfixturevalue(test_app)

    with test_app.app_context(), test_app.test_client() as c:
        rv = c.get(route)
        assert rv.status_code == 200
        assert rv.headers.get('Content-Security-Policy') == csp_state
        assert rv.headers.get('Content-Security-Policy-Report-Only') == csp_report_state


@pytest.mark.parametrize('report_to, csp_state, report_to_state', [
    (
        'csp-endpoint',
        "default-src 'self'; report-to csp-endpoint",
        None,
    ),
    (
        {'name': 'csp-endpoint', 'endpoints': 'https://example.com/csp/receiver'},
        "default-src 'self'; report-to csp-endpoint",
        '{"endpoints": [{"url": "https://example.com/csp/receiver"}], "group": "csp-endpoint", "max_age": 3600}',
    ),
    (
        [
            {'name': 'csp-endpoint', 'endpoints': 'https://example.com/csp/receiver', 'max_age': 60},
            {'name': 'other-endpoint', 'endpoints': ['https://example.com/other/receiver']},
        ],
        "default-src 'self'; report-to csp-endpoint",
        (
            '{"endpoints": [{"url": "https://example.com/csp/receiver"}], "group": "csp-endpoint", "max_age": 60},'
            '{"endpoints": [{"url": "https://example.com/other/receiver"}], "group": "other-endpoint", "max_age": 3600}'
        ),
    ),
])
def test_extension_report_to(base_app, report_to, csp_state, report_to_state):
    """Ensure that report_to names a single group in the CSP and defines groups in Report-To"""

    CSP(base_app, report_to=report_to)

    with base_app.test_client() as c:
        rv = c.get('/undecorated')
        assert rv.headers.get('Content-Security-Policy') == csp_state
        assert rv.headers.get('Report-To') == report_to_state


def test_extension_report_only_with_report_to_group(base_app):
    """Ensure that a report_to group satisfies the report-only policy requirement"""

    CSP(base_app, report_only=True, report_to={
        'name': 'csp-endpoint',
        'endpoints': 'https://example.com/csp/receiver',
    })

    with base_app.test_client() as c:
        rv = c.get('/undecorated')
        assert rv.headers.get('Content-Security-Policy-Report-Only') == (
            "default-src 'self'; report-to csp-endpoint"
        )
