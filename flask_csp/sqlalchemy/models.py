"""
flask_csp.sqlalchemy.models
"""

from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base for the Flask-CSP models"""


class CspReport(Base):
    """

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

    Reference:

    https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only

    """

    __tablename__ = "csp_reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(default=func.now())

    blocked_uri: Mapped[str]
    disposition: Mapped[str]
    document_uri: Mapped[str]
    effective_directive: Mapped[str | None]
    original_policy: Mapped[str]
    referrer: Mapped[str | None]
    script_sample: Mapped[str | None]
    status_code: Mapped[int | None]
    violated_directive: Mapped[str | None]
