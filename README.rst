Flask-CSP
=========

A Flask extension for including Content-Security-Policy (CSP) headers in responses that Flask builds.

There are 4 ways to use this extension:

- global: covering the entire app with a single policy
- blueprint: covering a specific blueprint with a single policy
- individual views: using a decorator that can have a specific policy for each view
- mixed: using any combination of the global, blueprint and decorator to override specific views

*Note:* When mixing the methods, the decorator takes precedence and will override blueprint or
 global settings. The blueprint will override global settings. And the global settings will cover
 anything that hasn't been already handled via blueprints or decorators.


Installation
------------

.. code:: bash

    $ pip install "flask-csp @ git+https://github.com/fictive-kin/flask-csp.git"


Global App-level extension
--------------------------

.. code:: python

    from flask import Flask
    from flask_csp import CSP

    app = Flask(__name__)
    CSP(app)

    @app.route("/")
    def index():
      return "Hello, with a very simple default CSP policy!"


Blueprint-level extension
--------------------------

.. code:: python

    from flask import Flask, Blueprint
    from flask_csp import CSP

    app = Flask(__name__)
    csp = CSP()

    bp = Blueprint('csp_covered', __name__)
    csp.init_blueprint(
        bp,
        default_src=['data:', 'https:', 'self'],
        upgrade_insecure_requests=True
    )

    @bp.route("/")
    def blueprint_index():
        return "Hello, with a non-default CSP policy!"

    @app.route("/")
    def index():
        return "Hello, with no CSP policy set!"

    app.register_blueprint(bp, url_prefix='/my-blueprint')


As a decorator
--------------

.. code:: python

    from flask import Flask
    from flask_csp import csp

    app = Flask(__name__)

    @app.route("/")
    @csp
    def index():
        return "Hello, with a very simple default CSP policy!"

    @app.route("/report-only")
    @csp(report_only=True, report_uri="https://example.com/csp/receiver")
    def report_only():
        return "This will have the Content-Security-Policy-Report-Only header"


Mixed use of extension and decorator
------------------------------------

.. code:: python

    from flask import Flask
    from flask_csp import CSP, csp

    app = Flask(__name__)
    CSP(app)

    @app.route("/")
    def index():
        return "Hello, with a very simple default CSP policy set by the extension!"

    @app.route("/report-only")
    @csp(report_only=True, report_uri="https://example.com/csp/receiver")
    def report_only():
        return "This will have the Content-Security-Policy-Report-Only header"
