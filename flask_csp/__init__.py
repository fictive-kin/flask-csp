"""
flask_csp
~~~~
Flask-CSP is a simple extension to Flask allowing you to return
Content Security Policies (CSP) using a simple decorator.
"""

from .core import apply_csp
from .decorator import csp, standalone_csp
from .extension import CSP
from .policy import meta_policy, meta_tag

__all__ = ["CSP", "apply_csp", "csp", "meta_policy", "meta_tag", "standalone_csp"]
