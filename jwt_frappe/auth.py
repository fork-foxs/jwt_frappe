import frappe
from frappe.auth import CookieManager, HTTPRequest, LoginManager
from frappe.translate import get_lang_code


class CookieManagerJWT(CookieManager, object):
	def flush_cookies(self, response):
		# use this opportunity to set the response headers
		response.headers["X-Client-Site"] = frappe.local.site
		if frappe.flags.jwt_clear_cookies:
			# Case when right after login with use_jwt=1
			# We set the flag on session_creation — clear all cookies
			# so the client never receives a sid cookie
			self.cookies = frappe._dict()
		if frappe.flags.jwt:
			# Case when the incoming request has jwt token
			# We leave cookies untouched (there can be other browser tabs)
			return
		return super(CookieManagerJWT, self).flush_cookies(response)


class AnvilHTTPRequest(HTTPRequest):
	def __init__(self):
		# Get Environment variables
		self.domain = frappe.request.host
		if self.domain and self.domain.startswith('www.'):
			self.domain = self.domain[4:]

		if frappe.get_request_header('X-Forwarded-For'):
			frappe.local.request_ip = (frappe.get_request_header(
					'X-Forwarded-For').split(",")[0]).strip()

		elif frappe.get_request_header('REMOTE_ADDR'):
			frappe.local.request_ip = frappe.get_request_header('REMOTE_ADDR')

		else:
			frappe.local.request_ip = '127.0.0.1'

		# language
		self.set_lang()

		# JWT Detection — check *before* session resume
		jwt_token = self._extract_jwt_token()

		if jwt_token:
			# When a JWT is present, we MUST prevent Frappe from resuming
			# a stale/corrupted session via the sid cookie. This is the
			# root cause of "User None is disabled" errors.
			headers = frappe._dict(frappe.request.headers)
			headers["Authorization"] = f"Bearer {jwt_token}"
			frappe.request.headers = headers
			# Strip sid from form_dict AND from cookies so Session.__init__
			# falls back to "Guest" sid instead of trying to resume a
			# potentially broken server session.
			frappe.local.form_dict.pop("sid", None)
			if hasattr(frappe.request, 'cookies'):
				frappe.request.cookies.pop("sid", None)

		# load cookies — use our JWT-aware cookie manager
		frappe.local.cookie_manager = CookieManagerJWT()

		# login / session resume
		self._init_session()

		if frappe.form_dict._lang:
			lang = get_lang_code(frappe.form_dict._lang)
			if lang:
				frappe.local.lang = lang

		self.validate_csrf_token()

		# write out latest cookies
		frappe.local.cookie_manager.init_cookies()

	def _extract_jwt_token(self):
		"""Extract JWT token from Authorization header or query params.

		Returns the token string if found, None otherwise.
		"""
		auth_header = frappe.get_request_header("Authorization")
		if auth_header:
			parts = auth_header.split(" ")
			# Accept raw token (not basic/bearer/token scheme)
			if parts[0].lower() not in ("basic", "bearer") and ":" not in parts[-1]:
				return parts[-1]

		# Private file access via query param
		if (frappe.request.path.startswith('/private/files/')
				and frappe.request.args.get("token")):
			return frappe.request.args.get("token")

		return None

	def _init_session(self):
		"""Initialize LoginManager with a safe fallback for corrupted sessions.

		When JWT is in use but the sid cookie points to a corrupt/expired
		session, Frappe throws ValidationError ("User None is disabled").
		We catch this and fall back to Guest — the auth_hooks
		(validate_cached_token) will then promote to the correct user.
		"""
		try:
			frappe.local.login_manager = LoginManager()
		except (frappe.ValidationError, frappe.AuthenticationError):
			# Session resume failed (e.g. user=None, disabled user,
			# expired session with corrupted state).
			# Create a clean Guest session so auth_hooks can take over.
			frappe.local.login_manager = frappe.local.login_manager if hasattr(frappe.local, 'login_manager') else object.__new__(LoginManager)
			frappe.local.login_manager.user = "Guest"
			frappe.local.login_manager.info = None
			frappe.local.login_manager.full_name = None
			frappe.local.login_manager.user_type = None
			frappe.local.login_manager.resume = False
			frappe.local.login_manager.make_session()
