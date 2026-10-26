"""
flask_csp.utils
"""

import json
import logging

from flask import abort, request

LOG = logging.getLogger("flask_csp.receiver")


def get_submitted_report():
    """
    Returns the report that was submitted as part of this request
    """

    if request.content_type != "application/csp-report":
        return abort(400)

    csp_report = json.loads(request.data).get("csp-report", {})
    if not csp_report:
        return abort(400)

    LOG.info(json.dumps(csp_report, indent=4, sort_keys=True))

    return csp_report
