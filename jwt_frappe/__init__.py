# -*- coding: utf-8 -*-
from __future__ import unicode_literals
try:
    import frappe
except ImportError:
    frappe = None
from frappe.utils import cint

__version__ = '1.0.2'


def _install_jwt_cookie_manager():
    """Replace the standard CookieManager with JWT-aware version.

    This ensures cookies (especially sid) are suppressed on JWT responses,
    regardless of whether the custom WSGI app or standard frappe.app is used.
    """
    from jwt_frappe.auth import CookieManagerJWT

    cm = getattr(frappe.local, "cookie_manager", None)
    if cm and not isinstance(cm, CookieManagerJWT):
        jwt_cm = CookieManagerJWT()
        jwt_cm.cookies = cm.cookies
        jwt_cm.to_delete = cm.to_delete
        frappe.local.cookie_manager = jwt_cm


def on_session_creation(login_manager):
    try:
        from jwt_frappe.utils.auth import get_bearer_token
        from jwt_frappe.utils.token_store import resolve_login_token_expiry
        if frappe.form_dict.get('use_jwt') and cint(frappe.form_dict.get('use_jwt')):
            expires_in = resolve_login_token_expiry()
            token = get_bearer_token(
                user=login_manager.user,
                expires_in=expires_in
            )
            frappe.local.response['expires_in'] = token.get("expires_in", expires_in)
            frappe.local.response['token'] = token["access_token"]
            frappe.local.response['refresh_token'] = token["refresh_token"]
            frappe.flags.jwt_clear_cookies = True
            # Swap cookie manager so flush_cookies suppresses sid/user cookies
            _install_jwt_cookie_manager()
    except ImportError:
        pass


@frappe.whitelist()
def get_logged_user():
  user = frappe.session.user
