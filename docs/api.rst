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

Storing reports with SQLAlchemy
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Reports can be saved to a database instead of logged. This needs SQLAlchemy 2.0 or later, which
the ``full`` extra installs:

.. code:: bash

    $ pip install "flask-csp[full] @ git+https://github.com/fictive-kin/flask-csp.git"

Pass an SQLAlchemy ``Engine``, or anything that returns a ``Session`` when called (such as a
``sessionmaker``), as the ``sqlalchemy`` argument. Reports are saved to a ``csp_reports`` table,
which you need to create, for example with ``Base.metadata.create_all`` or a migration:

.. code:: python

    from flask import Flask
    from flask_csp import CSP
    from flask_csp.sqlalchemy.models import Base
    from sqlalchemy import create_engine

    engine = create_engine('postgresql://localhost/example')
    Base.metadata.create_all(engine)

    app = Flask(__name__)
    CSP(app, receiver_prefix='/csp', report_uri='/csp/report', sqlalchemy=engine)

With `Flask-SQLAlchemy <https://flask-sqlalchemy.readthedocs.io/>`__, pass ``db.session``:

.. code:: python

    db = SQLAlchemy(app)
    CSP(app, receiver_prefix='/csp', report_uri='/csp/report', sqlalchemy=db.session)

    with app.app_context():
        Base.metadata.create_all(db.engine)

``db.create_all()`` does not create the ``csp_reports`` table, since it uses its own metadata.

Reports can be browsed at ``<receiver_prefix>/reports/review``. A ``POST`` to the same URL
filters them by any of these form fields:

* ``before`` / ``after``: ISO 8601 timestamps
* ``disposition``: ``enforce`` or ``report``
* ``document-uri``, ``blocked-uri``, ``referrer``: matches any report containing the value

.. warning::

   The review page has no access control, and reports can include URLs and referrers from your
   users' sessions. Protect it, for example with a ``before_request`` handler on the app, before
   exposing it publicly.

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
