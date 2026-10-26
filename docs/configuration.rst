Configuration
=============

Flask-CSP can be configured in several places. For each option, the first of these that sets it
is used:

   #. Keyword arguments to ``init_app``, ``init_blueprint`` or the :py:func:`~flask_csp.csp`
      decorator
   #. Keyword arguments to the :py:class:`~flask_csp.CSP` constructor
   #. App configuration settings (e.g. ``CSP_SCRIPT_SRC``)
   #. :ref:`Default settings <csp_default_values>`

.. note::

   * Blueprints have no config of their own, so policies set up with ``init_blueprint`` ignore the
     app's ``CSP_*`` settings.
   * The decorator only combines its own arguments with the app's ``CSP_*`` settings; it does not
     inherit arguments passed to the extension.
   * When more than one policy covers a view, only one header is sent: the decorator wins over a
     blueprint policy, which wins over the app-wide policy.

Option names
~~~~~~~~~~~~

Each CSP directive is an option named after the directive, in lower case with underscores in place
of hyphens. For example, the ``script-src`` directive can be set with the keyword argument
``script_src`` or the app config key ``CSP_SCRIPT_SRC``.

.. code:: python

    app.config['CSP_SCRIPT_SRC'] = ['self', 'https://cdn.example.com']

    CSP(app, img_src=['self', 'data:'], upgrade_insecure_requests=True)

produces::

    Content-Security-Policy: default-src 'self'; img-src 'self' data:; script-src 'self' https://cdn.example.com; upgrade-insecure-requests

Values
~~~~~~

An option's value can be a single value or a list of them. Options set to ``None`` or an empty
value are left out of the header.

Keywords such as ``'self'``, ``'none'``, ``'unsafe-inline'`` or ``'strict-dynamic'`` can be given
with or without their single quotes, and are quoted in the header automatically. The same goes for
scheme sources (``data:``, ``blob:``, ``https:``), which may be given with or without the trailing
colon. They can also be passed as members of :py:class:`flask_csp.constants.FetchRestriction`.

Anything else (hosts, wildcard hosts, URLs, ``'nonce-...'`` and ``'sha256-...'`` sources) is
included as given.

Some directives take restricted values:

``sandbox``
   Members of :py:class:`flask_csp.constants.SandboxRestriction`, e.g. ``allow-scripts``.

``trusted_types``
   Policy names, ``'none'`` or ``'allow-duplicates'``.

``report_uri``
   A single URL.

``upgrade_insecure_requests``
   Takes no value; set it to ``True`` to include it.

Supported directives
~~~~~~~~~~~~~~~~~~~~

Fetch directives
   ``child_src``, ``connect_src``, ``default_src``, ``font_src``, ``frame_src``, ``img_src``,
   ``manifest_src``, ``media_src``, ``object_src``, ``prefetch_src``, ``script_src``,
   ``script_src_elem``, ``script_src_attr``, ``style_src``, ``style_src_elem``,
   ``style_src_attr``, ``worker_src``, ``plugin_src`` (deprecated)

Document directives
   ``base_uri``, ``sandbox``

Navigation directives
   ``form_action``, ``frame_ancestors``, ``navigate_to``

Reporting directives
   ``report_uri``

Other directives
   ``require_sri_for``, ``require_trusted_types_for``, ``trusted_types``,
   ``upgrade_insecure_requests``

Other options
~~~~~~~~~~~~~

``report_only`` / ``CSP_REPORT_ONLY`` (:py:class:`bool`)
   Send the policy as ``Content-Security-Policy-Report-Only`` instead of
   ``Content-Security-Policy``. Requires a ``report_uri``.

``intercept_exceptions`` (:py:class:`bool`, extension only)
   Whether to also add the header to responses produced by Flask's exception handlers.
   Defaults to ``True``.

``receiver_prefix`` (:py:class:`str`, extension only)
   The URL prefix to mount the built-in report receiver at. See :ref:`receiving reports
   <receiving-reports>`.

.. _csp_default_values:

Default values
~~~~~~~~~~~~~~

* ``default_src``: ``'self'``
* ``report_only``: ``False``
* All other directives: ``None`` (not sent)
