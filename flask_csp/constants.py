"""
flask_csp.constants
"""

from enum import Enum


class Directive(Enum):
    """Directives that together form a CSP"""

    # Fetch directives
    CHILD_SRC = 'child-src'
    CONNECT_SRC = 'connect-src'
    DEFAULT_SRC = 'default-src'
    FONT_SRC = 'font-src'
    FRAME_SRC = 'frame-src'
    IMG_SRC = 'img-src'
    MANIFEST_SRC = 'manifest-src'
    MEDIA_SRC = 'media-src'
    OBJECT_SRC = 'object-src'
    PLUGIN_SRC = 'plugin-src'            # deprecated
    PREFETCH_SRC = 'prefetch-src'        # experimental
    SCRIPT_SRC = 'script-src'
    SCRIPT_SRC_ELEM = 'script-src-elem'  # experimental
    SCRIPT_SRC_ATTR = 'script-src-attr'  # experimental
    STYLE_SRC = 'style-src'
    STYLE_SRC_ELEM = 'style-src-elem'    # experimental
    STYLE_SRC_ATTR = 'style-src-attr'    # experimental
    WORKER_SRC = 'worker-src'            # experimental

    # Document directives
    BASE_URI = 'base-uri'
    SANDBOX = 'sandbox'

    # Navigation directives
    FORM_ACTION = 'form-action'
    FRAME_ANCESTORS = 'frame-ancestors'
    NAVIGATE_TO = 'navigate-to'          # experimental

    # Reporting directives
    REPORT_TO = 'report-to'              # experimental
    REPORT_URI = 'report-uri'            # deprecated

    # Other directives
    REQUIRE_SRI_FOR = 'require-sri-for'                      # experimental
    REQUIRE_TRUSTED_TYPES_FOR = 'require-trusted-types-for'  # experimental
    TRUSTED_TYPES = 'trusted-types'                          # experimental
    UPGRADE_INSECURE_REQUESTS = 'upgrade-insecure-requests'


class FetchRestriction(Enum):
    """"Reserved words used as restrictions within the CSP policy"""

    # header output value requires the inclusion of the single quotes,
    # therefore, their values are all double-quoted to prevent needing to
    # handle the single-quoting at output time

    NONE = "'none'"
    SELF = "'self'"
    UNSAFE_INLINE = "'unsafe-inline'"
    UNSAFE_EVAL = "'unsafe-eval'"
    UNSAFE_HASHES = "'unsafe-hashes'"
    UNSAFE_ALLOW_REDIRECTS = "'unsafe-allow-redirects'"
    STRICT_DYNAMIC = "'strict-dynamic'"
    REPORT_SAMPLE = "'report-sample'"

    # The following are experimental values. Use at your own discretion.
    WASM_UNSAFE_EVAL = "'wasm-unsafe-eval'"

    # These values restrict by scheme and should _not_ be single quoted,
    # however, they _must_ end with a `:`
    HTTP = "http:"
    HTTPS = "https:"
    DATA = "data:"
    BLOB = "blob:"

    # Other restrictions can be a domain, a wildcard domain, either of those
    # with a scheme specified, a `nonce` value or a `sha*` hash. i.e.:
    #
    # `example.com` would allow all assets on example.com
    # `*.example.com` would allow all assets any subdomain of example.com
    # `https://example.com` would allow all assets retrieved over https on example.com
    # `nonce-asdfasdfasdfasdf` would allow only the script tag with a nonce attribute that matches
    #     the provided nonce in the header, and _must_ be different on every request
    # `sha256-47795047a22117d4ae0fbf672779de8aa6b2b094581672dd83652bc5552bbb71` would allow
    #     assets that match that sha256 checksum


class TrustedTypesRestriction(Enum):
    """Restrictions specific to TrustedTypes directive"""

    NONE = "'none'"
    ALLOW_DUPLICATES = "'allow-duplicates'"


class SandboxRestriction(Enum):
    """Restrictions specific to Sandbox directive"""

    ALLOW_DOWNLOADS = 'allow-downloads'
    ALLOW_FORMS = 'allow-forms'
    ALLOW_MODALS = 'allow-modals'
    ALLOW_ORIENTATION_LOCK = 'allow-orientation-lock'
    ALLOW_POINTER_LOCK = 'allow-pointer-lock'
    ALLOW_POPUPS = 'allow-popups'
    ALLOW_POPUPS_TO_ESCAPE_SANDBOX = 'allow-popups-to-escape-sandbox'
    ALLOW_PRESENTATION = 'allow-presentation'
    ALLOW_SAME_ORIGIN = 'allow-same-origin'
    ALLOW_SCRIPTS = 'allow-scripts'
    ALLOW_TOP_NAVIGATION = 'allow-top-navigation'
    ALLOW_TOP_NAVIGATION_BY_USER_ACTIVATION = 'allow-top-navigation-by-user-activation'

    # experimental
    ALLOW_DOWNLOADS_WITHOUT_USER_ACTIVATION = 'allow-downloads-without-user-activation'
    ALLOW_STORAGE_ACCESS_BY_USER_ACTIVATION = 'allow-storage-access-by-user-activation'


# Attribute added to request object by decorator to indicate that CSP
# was evaluated, in case the decorator and extension are both applied
# to a view.
FLASK_CSP_EVALUATED = '_FLASK_CSP_EVALUATED'

DEFAULT_OPTIONS = {item.name.lower(): None for item in Directive}
DEFAULT_OPTIONS.update({
    'default_src': FetchRestriction.SELF,
    'report_only': False,
})
