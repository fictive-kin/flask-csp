API Docs
========

This package exposes a Flask extension, which adds a ``Content-Security-Policy`` header to every
response from an app or blueprint, and a decorator, which adds one to a single view.

Extension
~~~~~~~~~

The extension is the suggested approach. Pass any :doc:`configuration options <configuration>`
as keyword arguments, either to the constructor or to ``init_app`` / ``init_blueprint``.

.. autoclass:: flask_csp.CSP
   :members: init_app, init_blueprint

Decorator
~~~~~~~~~

If a view needs a different policy from the rest of the app, wrap it with the decorator. It accepts
the same options as the extension and can be used with or without arguments.

.. autofunction:: flask_csp.csp

Report-only policies
~~~~~~~~~~~~~~~~~~~~

Setting ``report_only=True`` sends the policy as ``Content-Security-Policy-Report-Only`` instead.
Browsers then report violations without blocking anything, which is a safe way to trial a policy
before enforcing it. A report-only policy must include a ``report_uri`` or ``report_to`` directive,
otherwise a :py:exc:`ValueError` is raised when the response is built.

.. code:: python

    from flask import Flask
    from flask_csp import CSP

    app = Flask(__name__)
    CSP(app, report_only=True, report_uri='https://example.com/csp/receiver')

.. _receiving-reports:

Receiving reports
~~~~~~~~~~~~~~~~~

Passing ``receiver_prefix`` to the extension registers a blueprint with a ``POST /report`` endpoint
that accepts ``application/csp-report`` submissions and writes each one to the
``flask_csp.receiver`` logger. Point your ``report_uri`` at it:

.. code:: python

    import logging

    from flask import Flask
    from flask_csp import CSP

    logging.getLogger('flask_csp.receiver').setLevel(logging.INFO)

    app = Flask(__name__)
    CSP(app, receiver_prefix='/csp', report_uri='/csp/report')

Without ``receiver_prefix``, no endpoint is registered and you will need to collect reports
yourself.

Policy objects
~~~~~~~~~~~~~~

The extension and decorator build their headers with these classes. They can also be used
directly to build a header value outside of a request.

.. code:: python

    >>> from flask_csp.policy import ContentSecurityPolicy, load_directive
    >>> policy = ContentSecurityPolicy(
    ...     load_directive('default_src', 'self'),
    ...     load_directive('img_src', 'self', 'data:'),
    ... )
    >>> str(policy)
    "Content-Security-Policy: default-src 'self'; img-src 'self' data:"

.. autofunction:: flask_csp.policy.load_directive

.. autoclass:: flask_csp.policy.ContentSecurityPolicy
   :members: add, value

.. autoclass:: flask_csp.policy.ReportOnlyPolicy
