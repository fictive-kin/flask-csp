# -*- coding: utf-8 -*-
"""
flask_csp.core
~~~~
Core functionality shared between the extension and the decorator.
"""

import logging

from flask import current_app
from werkzeug.datastructures import Headers, MultiDict

from .constants import Directive, FLASK_CSP_EVALUATED, DEFAULT_OPTIONS
from .policy import ReportGroup, ReportTo, ContentSecurityPolicy, ReportOnlyPolicy, load_directive


LOG = logging.getLogger(__name__)

# Options that change how the header is sent, rather than being directives within it
NON_DIRECTIVE_OPTIONS = ['report_only',]


def set_csp_header(resp, options):
    """
    Performs the actual evaluation of Flask-CSP options and actually
    modifies the response object.

    This function is used both in the decorator and the after_request
    callback
    """

    # If CSP has already been evaluated via the decorator, skip
    if hasattr(resp, FLASK_CSP_EVALUATED):
        LOG.debug('CSP has been already evaluated, skipping')
        return resp

    setattr(resp, FLASK_CSP_EVALUATED, True)

    # Some libraries, like OAuthlib, set resp.headers to non Multidict
    # objects (Werkzeug Headers work as well). This is a problem because
    # headers allow repeated values.
    if (not isinstance(resp.headers, Headers)
           and not isinstance(resp.headers, MultiDict)):
        resp.headers = MultiDict(resp.headers)

    report_groups = get_report_groups(options.get('report_to'))

    header = (ReportOnlyPolicy if options.get('report_only', False) else ContentSecurityPolicy)()
    for option, restrictions in options.items():
        if option in NON_DIRECTIVE_OPTIONS or not restrictions:
            continue
        # The report-to directive can only name a single group, which must be
        # defined in the Report-To header
        if option == 'report_to' and report_groups:
            restrictions = report_groups[0].name
        if not isinstance(restrictions, (list, set, tuple, )):
            restrictions = [restrictions]
        header.add(load_directive(option, *restrictions))

    LOG.debug('Settings CSP header: %s', header.value)
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

    if not isinstance(report_to, (list, set, tuple,)):
        report_to = [report_to]

    groups = []
    for group in report_to:
        if isinstance(group, ReportGroup):
            groups.append(group)
        elif isinstance(group, dict):
            groups.append(
                ReportGroup(group['name'],
                            group['endpoints'],
                            max_age=group.get('max_age', None))
            )

    return groups


def get_csp_options(app, *dicts):
    """
    Compute CSP options for an application by combining the DEFAULT_OPTIONS,
    the app's configuration-specified options and any dictionaries passed. The
    last specified option wins.
    """

    options = DEFAULT_OPTIONS.copy()
    options.update(get_app_kwarg_dict(app))
    if dicts:
        for dict_ in dicts:
            options.update(dict_)

    return options


def get_app_kwarg_dict(app=None):
    """Returns the dictionary of CSP specific app configurations."""

    app = (app or current_app)

    # In order to support blueprints which do not have a config attribute
    app_config = getattr(app, 'config', {})

    option_names = [k.name.lower() for k in Directive] + NON_DIRECTIVE_OPTIONS

    return {
        name: app_config.get(f'CSP_{name.upper()}')
        for name in option_names
        if app_config.get(f'CSP_{name.upper()}') is not None
    }
