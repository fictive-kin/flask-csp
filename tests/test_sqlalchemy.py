"""
tests.test_sqlalchemy
"""

import json

import pytest

sqlalchemy = pytest.importorskip('sqlalchemy')

# pylint: disable=wrong-import-position
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
    """A Flask app storing CSP reports with SQLAlchemy, given an Engine or a sessionmaker"""

    target = engine if request.param == 'engine' else sessionmaker(bind=engine)
    CSP(base_app, receiver_prefix='/csp', sqlalchemy=target)
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


def test_receiver_rejects_incomplete_report(sqlalchemy_app, minimal_csp_report):
    """Ensure that a report missing required fields is rejected"""

    del minimal_csp_report['csp-report']['blocked-uri']

    with sqlalchemy_app.test_client() as c:
        rv = post_report(c, minimal_csp_report)
        assert rv.status_code == 400


def test_review_lists_and_filters_reports(sqlalchemy_app, minimal_csp_report):
    """Ensure that the review page lists saved reports and applies filters"""

    with sqlalchemy_app.test_client() as c:
        post_report(c, minimal_csp_report)
        minimal_csp_report['csp-report']['document-uri'] = 'http://example.com/other.html'
        post_report(c, minimal_csp_report)

        rv = c.get('/csp/reports/review')
        assert rv.status_code == 200
        assert b'signup.html' in rv.data
        assert b'other.html' in rv.data

        rv = c.post('/csp/reports/review', data={'document-uri': 'signup'})
        assert rv.status_code == 200
        assert b'signup.html' in rv.data
        assert b'other.html' not in rv.data

        rv = c.post('/csp/reports/review', data={'after': 'not-a-date'})
        assert rv.status_code == 400


def test_sqlalchemy_rejects_invalid_target(base_app):
    """Ensure that a value which cannot create sessions is rejected"""

    with pytest.raises(ValueError):
        CSP(base_app, receiver_prefix='/csp', sqlalchemy=True)
