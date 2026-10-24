"""Webhook signature (X-Hub-Signature-256): only posts signed with a WhatsApp Account's App Secret are accepted."""

import hashlib
import hmac
import json

import frappe
try:  # v16: test records load lazily
	from frappe.tests import IntegrationTestCase as TestCase
except ImportError:  # v14/v15
	from frappe.tests.utils import FrappeTestCase as TestCase
from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Request

from frappe_whatsapp.utils.webhook import signature_ok

SECRET = "test-app-secret-123"


class TestWebhookSignature(TestCase):
	def setUp(self):
		frappe.flags.whatsapp_check_signature = True
		self.account = frappe.get_doc(
			{
				"doctype": "WhatsApp Account",
				"account_name": f"Sig test {frappe.generate_hash(length=6)}",
				"token": "x",
				"url": "https://graph.facebook.com",
				"version": "v19.0",
				"phone_id": frappe.generate_hash(length=10),
				"business_id": "1",
				"app_id": "1",
				"webhook_verify_token": frappe.generate_hash(length=8),
				"app_secret": SECRET,
				"status": "Active",
			}
		).insert(ignore_permissions=True)
		self._request = getattr(frappe.local, "request", None)

	def tearDown(self):
		frappe.flags.whatsapp_check_signature = False
		frappe.local.request = self._request

	def post(self, body: bytes, signature: str | None):
		headers = {"Content-Type": "application/json"}
		if signature is not None:
			headers["X-Hub-Signature-256"] = signature
		frappe.local.request = Request(EnvironBuilder(method="POST", data=body, headers=headers).get_environ())
		return signature_ok()

	def test_valid_signature(self):
		body = json.dumps({"entry": []}).encode()
		sig = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
		self.assertTrue(self.post(body, sig))

	def test_wrong_or_missing_signature(self):
		body = json.dumps({"entry": []}).encode()
		self.assertFalse(self.post(body, "sha256=" + "0" * 64))
		self.assertFalse(self.post(body, None))
		other = "sha256=" + hmac.new(b"another-secret", body, hashlib.sha256).hexdigest()
		self.assertFalse(self.post(body, other))

	def test_tampered_body(self):
		body = json.dumps({"entry": []}).encode()
		sig = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
		self.assertFalse(self.post(body + b" ", sig))
