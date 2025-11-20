import frappe
from frappe.sessions import get_expiry_in_seconds
from frappe.utils import cint, get_datetime, now, now_datetime

CACHE_PREFIX = "jwt_frappe:access_token"
DEFAULT_EXPIRY_SECONDS = 604800  # fallback to 7 days if settings are missing


def resolve_login_token_expiry() -> int:
	"""Return the TTL (in seconds) that should be used for freshly issued JWT tokens."""
	requested = frappe.form_dict.get("jwt_expires_in") or frappe.form_dict.get("token_ttl") or frappe.form_dict.get(
		"expires_in"
	)
	requested = cint(requested) if requested else 0
	if requested > 0:
		return requested

	conf_override = cint(frappe.conf.get("jwt_token_expiry") or 0) if getattr(frappe, "conf", None) else 0
	if conf_override > 0:
		return conf_override

	try:
		return cint(get_expiry_in_seconds())
	except Exception:
		return DEFAULT_EXPIRY_SECONDS


def _cache_key(token: str) -> str:
	return f"{CACHE_PREFIX}:{token}"


def cache_access_token(token: str, user: str, expires_in: int) -> None:
	"""Store the token in Redis so we can short-circuit DB lookups later on."""
	ttl = cint(expires_in)
	if ttl <= 0 or not token or not user:
		return

	frappe.cache().set_value(
		_cache_key(token),
		{"user": user, "issued_at": now()},
		expires_in_sec=ttl,
	)


def validate_cached_token() -> None:
	"""Auth hook that resolves the current request's bearer token via Redis (with DB fallback)."""
	session_user = getattr(frappe.session, "user", None)
	if session_user not in (None, "", "Guest"):
		return

	token = _extract_token_from_request()
	if not token:
		return

	data = _load_cached_session(token)
	if not data:
		return

	user = data.get("user")
	if not user:
		return

	is_enabled = frappe.db.get_value("User", user, "enabled")
	if is_enabled != 1:
		return

	frappe.set_user(user)
	frappe.local.form_dict.setdefault("_jwt_user", user)
	frappe.local.form_dict.setdefault("_jwt_session", data)


def _load_cached_session(token: str) -> dict | None:
	cached = frappe.cache().get_value(_cache_key(token), expires=True)
	if cached:
		return cached
	return _hydrate_cache_from_db(token)


def _hydrate_cache_from_db(token: str) -> dict | None:
	doc = frappe.db.get_value(
		"OAuth Bearer Token",
		token,
		["user", "status", "expiration_time"],
		as_dict=True,
	)

	if not doc:
		return None

	if doc.status == "Revoked":
		return None

	expiration_time = doc.expiration_time
	if isinstance(expiration_time, str):
		expiration_time = get_datetime(expiration_time)

	if not expiration_time:
		return None

	time_left = int((expiration_time - now_datetime()).total_seconds())
	if time_left <= 0:
		return None

	payload = {"user": doc.user, "expires_at": expiration_time.isoformat()}
	cache_access_token(token, doc.user, time_left)
	return payload


def _extract_token_from_request() -> str | None:
	auth_header = (frappe.get_request_header("Authorization") or "").strip()
	if auth_header:
		parts = auth_header.split(" ")
		if len(parts) == 2:
			scheme, value = parts[0].lower(), parts[1].strip()
			if scheme == "bearer":
				return value
			if scheme == "token" and ":" not in value:
				return value
		elif len(parts) == 1 and parts[0]:
			return parts[0].strip()

	request = getattr(frappe.local, "request", None)
	if request and request.path.startswith("/private/files/"):
		token = request.args.get("token")
		if token:
			return token

	for key in ("access_token", "token"):
		token = frappe.form_dict.get(key)
		if token:
			return token

	return None
