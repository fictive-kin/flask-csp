"""
flask_csp.extension
"""

import logging

from flask import Flask, Blueprint

from .core import get_csp_options, set_csp_header

from .simple.views import CSP_BP as simple_bp

try:
    from .sqlalchemy.views import CSP_BP as sqlalchemy_bp
    SQLALCHEMY = True
except ImportError:
    SQLALCHEMY = False

LOG = logging.getLogger(__name__)


class CSP:
    """
    Initializes Content Security Policies for the application. The
    policy arguments are identical to :py:func:`csp`.

    The settings for CSP are determined in the following order

    1. Keyword arguments to ``init_app`` or ``init_blueprint``
    2. Keyword arguments to the constructor
    3. App level configuration settings (e.g. CSP_*)
    4. Default settings

    :param app: The Flask app to initialize, if not calling ``init_app`` later
    :param receiver_prefix: URL prefix to mount the CSP report receiver at.
        No receiver is registered if this is not set.
    :param sqlalchemy: Store received reports with SQLAlchemy instead of logging them
    :param kwargs: CSP directives and options, see :doc:`configuration`
    """

    _options = {}
    _receiver_prefix = None
    _sqlalchemy = False

    def __init__(self, app=None, *, receiver_prefix=None, sqlalchemy=None, **kwargs):
        """CSP initializer"""

        self._options = {}
        if kwargs:
            self._options = kwargs

        self._receiver_prefix = receiver_prefix
        self._sqlalchemy = sqlalchemy

        if app is not None:
            self.init_app(app, receiver_prefix=receiver_prefix, sqlalchemy=sqlalchemy, **kwargs)

    def init_app(self, app, *, receiver_prefix=None, sqlalchemy=None, **kwargs):
        """App initialization for the extension"""

        if not isinstance(app, Flask):
            raise ValueError('Provided value was not a Flask app instance')

        self.setup_after_request(app, **kwargs)

        if receiver_prefix is not None:
            self._receiver_prefix = receiver_prefix
        if sqlalchemy is not None:
            self._sqlalchemy = sqlalchemy

        # These error handlers will still respect the behavior of the route
        if self._options.get('intercept_exceptions', True):
            def _after_request_decorator(f):  # pylint: disable=invalid-name
                def wrapped_function(*args, **kwargs):
                    return self.after_request(app.make_response(f(*args, **kwargs)))
                return wrapped_function

            if hasattr(app, 'handle_exception'):
                app.handle_exception = _after_request_decorator(
                    app.handle_exception)
                app.handle_user_exception = _after_request_decorator(
                    app.handle_user_exception)

        if self._receiver_prefix is None:
            LOG.info(
                'Report receiving is disabled. To enable automatically, set `receiver_prefix`.')
            return

        if self._sqlalchemy:
            if not SQLALCHEMY:
                raise ValueError(
                    'Cannot load SqlAlchemy CSP views. SqlAlchemy is not available')

            app.register_blueprint(sqlalchemy_bp, url_prefix=self._receiver_prefix)

        else:
            app.register_blueprint(simple_bp, url_prefix=self._receiver_prefix)

    def init_blueprint(self, blueprint, **kwargs):
        """Blueprint initialization for the extension"""

        if not isinstance(blueprint, Blueprint):
            raise ValueError('Provided value was not a Blueprint instance')

        self.setup_after_request(blueprint, **kwargs)

    def setup_after_request(self, app_or_bp, **kwargs):
        """Adds the CSP header handler to the after request flow"""

        # The resources and options may be specified in the App Config, the CSP constructor
        # or the kwargs to the call to init_app/init_blueprint.
        self._options = get_csp_options(app_or_bp, self._options, kwargs)

        app_or_bp.after_request(self.after_request)

    def after_request(self, resp):
        """After request handler that adds the CSP header"""

        return set_csp_header(resp, self._options)
