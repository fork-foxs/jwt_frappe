# -*- coding: utf-8 -*-
from __future__ import unicode_literals
try:
    import frappe
except ImportError:
    frappe = None
from frappe.utils import cint

__version__ = '1.0.2'

# def on_session_creation(login_manager):
#   from jwt_frappe.utils.auth import make_jwt
#   if frappe.form_dict.get('use_jwt') and cint(frappe.form_dict.get('use_jwt')):
#     frappe.local.response['token'] = make_jwt(
#         login_manager.user, frappe.flags.get('jwt_expire_on'))
#     frappe.flags.jwt_clear_cookies = True

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
            frappe.flags.jwt_clear_cookies = True
    except ImportError:
        pass

@frappe.whitelist()
def get_logged_user():
  user = frappe.session.user
