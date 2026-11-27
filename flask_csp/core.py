"""
flask_csp.core
~~~~
Core functionality shared between the extension and the decorator.
"""

import logging

from flask import current_app, request
from werkzeug.datastructures import Headers, MultiDict

from .constants import DEFAULT_OPTIONS, FLASK_CSP_EVALUATED, Directive
from .policy import (
    ContentSecurityPolicy,
    ReportGroup,
    ReportOnlyPolicy,
    ReportTo,
    load_directive,
)

LOG = logging.getLogger(__name__)

# Options that change how the header is sent, rather than being directives within it
NON_DIRECTIVE_OPTIONS = [
    "report_only",
    "intercept_exceptions",
]

# Where the extension records itself on an app (in ``app.extensions``) or
# blueprint (as an attribute), so ``apply_csp`` can find its policy
EXTENSION_KEY = "csp"


class Deferred:
    """
    An option value worked out for each response: ``func`` is called with the
    value the option would otherwise have had (``None`` if none).
    """

    def __init__(self, func, previous=None):
        self.func = func
        self.previous = previous

    def resolve(self):
        return self.func(resolve(self.previous))

    def __repr__(self):
        return f"Deferred({self.func!r}, {self.previous!r})"


def resolve(value):
    """The value an option has for the current response."""
    return value.resolve() if isinstance(value, Deferred) else value


def merge_options(base, *dicts):
    """
    Combine option dictionaries into a copy of ``base``, the last specified
    option winning. Callable values become :py:class:`Deferred`, so they can
    build on the value they replace when a response is made.
    """

    options = dict(base)
    for dict_ in dicts:
        for option, value in (dict_ or {}).items():
            previous = options.get(option)
            if isinstance(previous, Deferred) and previous.func is value:
                # The same option given again (CSP(app, ...) passes its
                # arguments to init_app too), not a second layer on top.
                continue
            if callable(value) and not isinstance(value, Deferred):
                value = Deferred(value, previous)
            options[option] = value
    return options


def apply_csp(resp):
    """
    Add the policy that covers ``resp`` to it now, rather than when the
    request ends: the blueprint's policy, if one was set up with
    :py:meth:`CSP.init_blueprint <flask_csp.CSP.init_blueprint>`, otherwise
    the app's. A response that has had its policy already, such as from a
    decorator, is left alone, as is one that no policy covers.

    Use it in an ``after_request`` function, or a view, that needs to read or
    change a response's policy. Must be called within a request.
    """

    if hasattr(resp, FLASK_CSP_EVALUATED):
        return resp

    for name in request.blueprints:
        blueprint = current_app.blueprints.get(name)
        if extension := getattr(blueprint, f"_flask_{EXTENSION_KEY}", None):
            return extension.after_request(resp)

    if extension := current_app.extensions.get(EXTENSION_KEY):
        return extension.after_request(resp)

    return resp


def set_csp_header(resp, options):
    """
    Performs the actual evaluation of Flask-CSP options and actually
    modifies the response object.

    This function is used both in the decorator and the after_request
    callback
    """

    # If CSP has already been evaluated via the decorator, skip
    if hasattr(resp, FLASK_CSP_EVALUATED):
        LOG.debug("CSP has been already evaluated, skipping")
        return resp

    setattr(resp, FLASK_CSP_EVALUATED, True)

    options = {option: resolve(value) for option, value in options.items()}

    # Some libraries, like OAuthlib, set resp.headers to non Multidict
    # objects (Werkzeug Headers work as well). This is a problem because
    # headers allow repeated values.
    if not isinstance(resp.headers, Headers) and not isinstance(
        resp.headers, MultiDict
    ):
        resp.headers = MultiDict(resp.headers)

    report_groups = get_report_groups(options.get("report_to"))

    header = (
        ReportOnlyPolicy if options.get("report_only", False) else ContentSecurityPolicy
    )()
    for option, restrictions in options.items():
        if option in NON_DIRECTIVE_OPTIONS or not restrictions:
            continue
        # The report-to directive can only name a single group, which must be
        # defined in the Report-To header
        if option == "report_to" and report_groups:
            restrictions = report_groups[0].name
        # A bare sandbox directive (every restriction applied) has no values
        if option == "sandbox" and restrictions is True:
            restrictions = []
        if not isinstance(
            restrictions,
            (
                list,
                set,
                tuple,
            ),
        ):
            restrictions = [restrictions]
        header.add(load_directive(option, *restrictions))

    LOG.debug("Settings CSP header: %s", header.value)
    resp.headers.add(header.key, header.value)

    if report_groups:
        report_to = ReportTo(report_groups)
        resp.headers.add(report_to.key, report_to.value)

    return resp


def get_report_groups(report_to):
    """
    Returns the ReportGroups defined by the report_to option. A plain string
    only names a group for the report-to directive, so defines no groups.
    """

    if not report_to:
        return []

    if not isinstance(
        report_to,
        (
            list,
            set,
            tuple,
        ),
    ):
        report_to = [report_to]

    groups = []
    for group in report_to:
        if isinstance(group, ReportGroup):
            groups.append(group)
        elif isinstance(group, dict):
            groups.append(
                ReportGroup(
                    group["name"],
                    group["endpoints"],
                    max_age=group.get("max_age", None),
                )
            )

    return groups


def get_csp_options(app, *dicts):
    """
    Compute CSP options for an application by combining the DEFAULT_OPTIONS,
    the app's configuration-specified options and any dictionaries passed. The
    last specified option wins.
    """

    return merge_options(DEFAULT_OPTIONS, get_app_kwarg_dict(app), *dicts)


def get_app_kwarg_dict(app=None):
    """Returns the dictionary of CSP specific app configurations."""

    app = app or current_app

    # In order to support blueprints which do not have a config attribute
    app_config = getattr(app, "config", {})

    option_names = [k.name.lower() for k in Directive] + NON_DIRECTIVE_OPTIONS

    return {
        name: app_config.get(f"CSP_{name.upper()}")
        for name in option_names
        if app_config.get(f"CSP_{name.upper()}") is not None
    }
