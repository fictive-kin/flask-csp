# -*- coding: utf-8 -*-
"""
flask_csp.decorator
~~~~
A decorator to protect a single Flask route with CSP
"""

import functools
import logging

from flask import make_response, current_app

from .core import get_csp_options, set_csp_header


LOG = logging.getLogger(__name__)


def csp(*args, **kwargs):
    """
    This function is the decorator which is used to wrap a Flask route with.

    It can be applied bare (``@csp``) for the default policy, or called with
    CSP directives and options (``@csp(script_src=['self'])``), see
    :doc:`configuration`. Options are combined with the app's CSP_* settings.
    """

    _options = kwargs

    def wrapper(f):  # pylint: disable=invalid-name
        LOG.debug("Enabling %s for csp using options: %s", f, _options)

        @functools.wraps(f)
        def decorated(*args, **kwargs):
            # Handle setting of Flask-CSP parameters
            options = get_csp_options(current_app, _options)

            resp = make_response(f(*args, **kwargs))

            return set_csp_header(resp, options)

        return decorated

    try:
        if callable(args[0]):
            return wrapper(args[0])

    except IndexError:
        pass

    return wrapper
