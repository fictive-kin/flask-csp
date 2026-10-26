"""
flask_csp.simple.views
"""

import logging

from flask import Blueprint, abort, make_response

from ..utils import get_submitted_report

LOG = logging.getLogger("flask_csp.receiver")
CSP_BP = Blueprint("csp", __name__)


@CSP_BP.route("/report", methods=["POST"])
def receiver():
    """
    A simple receiver that outputs CSP reports to the log

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

    get_submitted_report()
    return make_response("", 204)


@CSP_BP.route("/reports/review", methods=["GET", "POST"])
def review():
    """
    Lists and searches received reports

    NOTE: This does not work for the simple receiver, as parsing log files
          could lead to undesired information disclosure. This is here as a
          placeholder example for other Flask-CSP backend handlers.
    """

    return abort(404)
