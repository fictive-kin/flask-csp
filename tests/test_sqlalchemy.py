"""
tests.test_sqlalchemy
"""

import json

import pytest

sqlalchemy = pytest.importorskip('sqlalchemy')

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from flask_csp import CSP
from flask_csp.sqlalchemy.models import Base, CspReport


@pytest.fixture()
def engine():
    """An in-memory SQLite database with the Flask-CSP tables created"""

    engine = create_engine(
        'sqlite://',
        connect_args={'check_same_thread': False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture(params=['engine', 'sessionmaker'])
def sqlalchemy_app(request, base_app, engine):
    """
    A Flask app storing CSP reports with SQLAlchemy, given an Engine to the
    constructor or a sessionmaker to init_app
    """

    if request.param == 'engine':
        CSP(base_app, receiver_prefix='/csp', sqlalchemy=engine)
    else:
        CSP().init_app(base_app, receiver_prefix='/csp', sqlalchemy=sessionmaker(bind=engine))
    yield base_app


def post_report(client, report):
    """Submits a CSP report to the receiver"""

    return client.post(
        '/csp/report',
        data=json.dumps(report),
        content_type='application/csp-report',
    )


@pytest.mark.parametrize('report', ['minimal_csp_report', 'full_csp_report'])
def test_receiver_saves_report(request, sqlalchemy_app, engine, report):
    """Ensure that submitted reports are saved, with or without the optional fields"""

    report = request.getfixturevalue(report)

    with sqlalchemy_app.test_client() as c:
        rv = post_report(c, report)
        assert rv.status_code == 204

    with sessionmaker(bind=engine)() as session:
        saved = session.scalars(select(CspReport)).one()
        assert saved.blocked_uri == report['csp-report']['blocked-uri']
        assert saved.document_uri == report['csp-report']['document-uri']
        assert saved.status_code == report['csp-report'].get('status-code')
        assert saved.ts is not None


@pytest.mark.parametrize('break_report, drop_table, status_code', [
    (True, False, 400),
    (False, True, 422),
])
def test_receiver_rejects_unsaveable_report(
        sqlalchemy_app, engine, minimal_csp_report, break_report, drop_table, status_code):
    """Ensure that a report missing required fields, or which cannot be saved, is rejected"""

    if break_report:
        del minimal_csp_report['csp-report']['blocked-uri']
    if drop_table:
        Base.metadata.drop_all(engine)

    with sqlalchemy_app.test_client() as c:
        rv = post_report(c, minimal_csp_report)
        assert rv.status_code == status_code


@pytest.mark.parametrize('filters, signup_found, other_found', [
    ({}, True, True),
    ({'document-uri': 'signup', 'unknown': 'ignored', 'referrer': ''}, True, False),
    ({'blocked-uri': 'other.css'}, False, True),
    ({'referrer': 'example.com/home'}, False, True),
    ({'disposition': 'enforce'}, False, True),
    ({'after': '2000-01-01T00:00:00', 'before': '2100-01-01T00:00:00'}, True, True),
    ({'before': '2000-01-01T00:00:00'}, False, False),
])
def test_review_lists_and_filters_reports(
        sqlalchemy_app, minimal_csp_report, filters, signup_found, other_found):
    """Ensure that the review page lists saved reports and applies filters"""

    with sqlalchemy_app.test_client() as c:
        post_report(c, minimal_csp_report)
        minimal_csp_report['csp-report'].update({
            'document-uri': 'http://example.com/other.html',
            'blocked-uri': 'http://example.com/css/other.css',
            'referrer': 'http://example.com/home',
            'disposition': 'enforce',
        })
        post_report(c, minimal_csp_report)

        rv = c.post('/csp/reports/review', data=filters) if filters else c.get('/csp/reports/review')
        assert rv.status_code == 200
        assert (b'signup.html' in rv.data) == signup_found
        assert (b'other.html' in rv.data) == other_found


def test_review_rejects_invalid_dates(sqlalchemy_app):
    """Ensure that the review page rejects date filters that cannot be parsed"""

    with sqlalchemy_app.test_client() as c:
        rv = c.post('/csp/reports/review', data={'after': 'not-a-date'})
        assert rv.status_code == 400


def test_sqlalchemy_rejects_invalid_target(base_app, engine, monkeypatch):
    """Ensure that a value which cannot create sessions, or missing SQLAlchemy, is rejected"""

    with pytest.raises(ValueError):
        CSP(base_app, receiver_prefix='/csp', sqlalchemy=True)

    monkeypatch.setattr('flask_csp.extension.SQLALCHEMY', False)
    with pytest.raises(ValueError):
        CSP(base_app, receiver_prefix='/csp', sqlalchemy=engine)
