"""
flask_csp.decorator
~~~~
Decorators to protect a single Flask route with CSP
"""

import functools
import logging

from flask import current_app, make_response

from .core import get_csp_options, merge_options, set_csp_header

LOG = logging.getLogger(__name__)


def _decorate(f, get_options):
    """Wrap ``f`` so that its response gets the policy ``get_options()`` returns."""

    @functools.wraps(f)
    def decorated(*args, **kwargs):
        resp = make_response(f(*args, **kwargs))
        return set_csp_header(resp, get_options())

    return decorated


def csp(*args, **kwargs):
    """
    This function is the decorator which is used to wrap a Flask route with.

    It can be applied bare (``@csp``) for the default policy, or called with
    CSP directives and options (``@csp(script_src=['self'])``), see
    :doc:`configuration`. Options are combined with the app's CSP_* settings;
    a callable option is passed the setting's value, so it can add to it.
    """

    _options = kwargs

    def wrapper(f):
        LOG.debug("Enabling %s for csp using options: %s", f, _options)
        return _decorate(f, lambda: get_csp_options(current_app, _options))

    try:
        if callable(args[0]):
            return wrapper(args[0])

    except IndexError:
        pass

    return wrapper


def standalone_csp(**kwargs):
    """
    Wrap a view, or any function returning a response, with a policy made only
    from the given CSP directives and options (see :doc:`configuration`).

    Unlike :py:func:`csp`, the app's ``CSP_*`` settings and the default
    ``default_src`` are not applied, so the header holds exactly the directives
    given, in the order given. Use it where the app-wide policy doesn't fit at
    all, such as for sandboxed, user-supplied content. As with :py:func:`csp`,
    the response doesn't also get the extension's policy.
    """

    if not kwargs:
        raise TypeError("standalone_csp needs at least one directive")

    _options = merge_options({}, kwargs)

    def wrapper(f):
        LOG.debug("Enabling %s for standalone csp using options: %s", f, _options)
        return _decorate(f, lambda: _options)

    return wrapper
