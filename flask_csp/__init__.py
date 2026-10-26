"""
flask_csp
~~~~
Flask-CSP is a simple extension to Flask allowing you to return
Content Security Policies (CSP) using a simple decorator.
"""

from .decorator import csp
from .extension import CSP

__all__ = ["CSP", "csp"]
