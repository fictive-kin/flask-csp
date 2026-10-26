"""
flask_csp.sqlalchemy.views
"""

import logging
from datetime import datetime

from flask import Blueprint, abort, current_app, make_response, render_template, request
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

try:
    from sentry_sdk import capture_exception

    SENTRY = True
except ImportError:
    SENTRY = False

from ..utils import get_submitted_report
from .models import CspReport

LOG = logging.getLogger("flask_csp.receiver")
CSP_BP = Blueprint("csp", __name__, template_folder="../templates")

# Key in app.extensions holding the session factory used by these views
EXTENSION_KEY = "flask_csp.sqlalchemy"


def get_session_factory(engine_or_factory):
    """
    Returns a callable that creates sessions, from either an Engine or an
    existing session factory such as a sessionmaker or scoped_session
    """

    if isinstance(engine_or_factory, Engine):
        return sessionmaker(bind=engine_or_factory)

    if not callable(engine_or_factory):
        raise ValueError(
            "sqlalchemy must be an Engine or a callable that returns a Session"
        )

    return engine_or_factory


def _get_session():
    return current_app.extensions[EXTENSION_KEY]()


@CSP_BP.route("/report", methods=["POST"])
def receiver():
    """
    A receiver that saves CSP reports to the database

    Example CSP report:

        {
          "csp-report": {
            "document-uri": "http://example.com/signup.html",
            "referrer": "",
            "blocked-uri": "http://example.com/css/style.css",
            "violated-directive": "style-src cdn.example.com",
            "original-policy":
                "default-src 'none'; style-src cdn.example.com; report-uri /_/csp-reports",
            "disposition": "report"
          }
        }

    """

    csp_report = get_submitted_report()

    # These 2 try blocks are separate to enable returning a 400 or 422 depending on
    # if the provided data was broken or there was an error saving the report to the db
    try:
        status_code = csp_report.get("status-code")
        report = CspReport(
            blocked_uri=csp_report["blocked-uri"],
            disposition=csp_report["disposition"],
            document_uri=csp_report["document-uri"],
            effective_directive=csp_report.get("effective-directive"),
            original_policy=csp_report["original-policy"],
            referrer=csp_report.get("referrer"),
            script_sample=csp_report.get("script-sample"),
            status_code=int(status_code) if status_code is not None else None,
            violated_directive=csp_report.get("violated-directive"),
        )

    except Exception as exc:
        if SENTRY:
            capture_exception(exc)

        LOG.exception("Could not parse CSP report")
        return abort(400)

    try:
        with _get_session() as session:
            session.add(report)
            session.commit()

    except Exception as exc:
        if SENTRY:
            capture_exception(exc)

        LOG.exception("Could not save CSP report")
        return abort(422)

    return make_response("", 204)


@CSP_BP.route("/reports/review", methods=["GET", "POST"])
def review():
    """
    Lists and allows searching of saved CSP reports
    """

    filters = []
    if request.method == "POST":
        for filter_, value in request.values.items():
            if not value:
                continue

            if filter_ in ("before", "after"):
                try:
                    value = datetime.fromisoformat(value)
                except ValueError:
                    return abort(400)

            if filter_ == "before":
                filters.append(CspReport.ts <= value)

            elif filter_ == "after":
                filters.append(CspReport.ts >= value)

            elif filter_ == "disposition":
                filters.append(CspReport.disposition == value)

            elif filter_ == "document-uri":
                filters.append(CspReport.document_uri.ilike(f"%{value}%"))

            elif filter_ == "blocked-uri":
                filters.append(CspReport.blocked_uri.ilike(f"%{value}%"))

            elif filter_ == "referrer":
                filters.append(CspReport.referrer.ilike(f"%{value}%"))

            # else: not a parameter that we care about

    with _get_session() as session:
        reports = session.scalars(
            select(CspReport).where(*filters).order_by(CspReport.id.desc())
        ).all()

        return render_template("reports/list.html", reports=reports)
