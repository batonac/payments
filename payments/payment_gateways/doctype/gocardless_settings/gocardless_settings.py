# Copyright (c) 2018, Frappe Technologies and contributors
# For license information, please see license.txt


from datetime import datetime, timedelta
from urllib.parse import urlencode

import frappe
import gocardless_pro
from frappe import _
from frappe.integrations.utils import create_request_log
from frappe.model.document import Document
from frappe.utils import call_hook_method, cint, flt, get_url
from frappe.utils.background_jobs import is_job_enqueued
from frappe.utils.scheduler import is_scheduler_inactive


class GoCardlessSettings(Document):
	# begin: auto-generated types
	# This code is auto-generated. Do not modify anything in this block.

	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		access_token: DF.Data
		fees_account: DF.Link | None
		gateway_name: DF.Data
		header_img: DF.AttachImage | None
		use_sandbox: DF.Check
		webhooks_secret: DF.Data | None
	# end: auto-generated types

	supported_currencies = ("EUR", "DKK", "GBP", "SEK", "AUD", "NZD", "CAD", "USD")

	def validate(self):
		self.initialize_client()

	def initialize_client(self):
		self.environment = self.get_environment()
		try:
			self.client = gocardless_pro.Client(access_token=self.access_token, environment=self.environment)
			return self.client
		except Exception as e:
			frappe.throw(e)

	def on_update(self):
		from payments.utils import create_payment_gateway

		create_payment_gateway(
			"GoCardless-" + self.gateway_name,
			settings="GoCardless Settings",
			controller=self.gateway_name,
		)
		call_hook_method("payment_gateway_enabled", gateway="GoCardless-" + self.gateway_name)

	def on_payment_request_submission(self, data):
		if data.reference_doctype != "Fees":
			customer_data = frappe.db.get_value(
				data.reference_doctype,
				data.reference_name,
				["company", "customer_name"],
				as_dict=1,
			)

		data = {
			"amount": flt(data.grand_total, data.precision("grand_total")),
			"title": customer_data.company.encode("utf-8"),
			"description": data.subject.encode("utf-8"),
			"reference_doctype": data.doctype,
			"reference_docname": data.name,
			"payer_email": data.email_to or frappe.session.user,
			"payer_name": customer_data.customer_name,
			"order_id": data.name,
			"currency": data.currency,
			"charge_date": data.transaction_date or frappe.utils.getdate(),
		}

		valid_mandate, next_possible_charge_date = self.check_mandate_validity(data)
		if valid_mandate is not None:
			data.update(valid_mandate)
			data["charge_date"] = str(
				max(
					data.get("charge_date"),
					frappe.utils.getdate(next_possible_charge_date),
				)
			)
			print("on_payment_request_submission", data)
			try:
				self.create_payment_request(data)
				print("create_payment_request completed successfully")
			except Exception as e:
				print("create_payment_request failed", str(e))
				raise  # Re-raise to see the full traceback
			return False
		else:
			print("No valid mandate found for customer", data.get("payer_name"))
			return True

	def check_mandate_validity(self, data):
		if frappe.db.exists("GoCardless Mandate", dict(customer=data.get("payer_name"), disabled=0)):
			registered_mandate = frappe.db.get_value(
				"GoCardless Mandate",
				dict(customer=data.get("payer_name"), disabled=0),
				"mandate",
			)
			self.initialize_client()
			mandate = self.client.mandates.get(registered_mandate)

			invalid_statuses = [
				"blocked",
				"cancelled",
				"consumed",
				"expired",
				"failed",
				"suspended_by_payer",
			]

			if mandate.status in invalid_statuses:
				frappe.db.set_value(
					"GoCardless Mandate",
					dict(customer=data.get("payer_name"), disabled=0),
					"disabled",
					1,
				)
				return None, None
			else:
				return {"mandate": registered_mandate}, mandate.next_possible_charge_date
		else:
			return None, None

	def get_environment(self):
		if self.use_sandbox:
			return "sandbox"
		else:
			return "live"

	def validate_transaction_currency(self, currency):
		if currency not in self.supported_currencies:
			frappe.throw(
				_(
					"Please select another payment method. Go Cardless does not support transactions in currency '{0}'"
				).format(currency)
			)

	def get_payment_url(self, **kwargs):
		return get_url(f"gocardless_checkout?{urlencode(kwargs)}")

	def create_payment_request(self, data):
		self.data = frappe._dict(data)

		try:
			self.integration_request = create_request_log(self.data, "Host", "GoCardless")
			frappe.get_doc(
				{
					"doctype": "Comment",
					"reference_doctype": self.data.reference_doctype,
					"reference_name": self.data.reference_docname,
					"comment_type": "Info",
					"content": f'Payment Requested via GoCardless. See the <a href="{self.integration_request.get_url()}">payment request</a> for more details.',
				}
			).insert(ignore_permissions=True)
			return self.create_charge_on_gocardless()

		except Exception as e:
			frappe.log_error("Gocardless payment request failed", str(e))
			return {
				"redirect_to": frappe.redirect_to_message(
					_("Server Error"),
					_(
						"There seems to be an issue with the server's GoCardless configuration. Don't worry, in case of failure, the amount will get refunded to your account."
					),
				),
				"status": 401,
			}

	def create_charge_on_gocardless(self):
		redirect_to = self.data.get("redirect_to") or None
		redirect_message = self.data.get("redirect_message") or None

		reference_doc = frappe.get_doc(self.data.get("reference_doctype"), self.data.get("reference_docname"))
		self.initialize_client()

		try:
			payment = self.client.payments.create(
				params={
					"amount": cint(reference_doc.grand_total * 100),
					"charge_date": self.data.get("charge_date"),
					"currency": reference_doc.currency,
					"links": {"mandate": self.data.get("mandate")},
					"metadata": {
						"reference_doctype": reference_doc.doctype,
						"reference_document": reference_doc.name,
					},
				},
				headers={
					"Idempotency-Key": self.data.get("reference_docname"),
				},
			)

			self.integration_request.db_set("output", payment.api_response._response._content.decode())

			match payment.status:
				case "pending_submission" | "pending_customer_approval" | "submitted":
					self.integration_request.db_set("status", "Authorized", update_modified=False)
					self.flags.status_changed_to = "Completed"
					self.integration_request.db_set("output", payment.status, update_modified=False)

				case "confirmed" | "paid_out":
					self.integration_request.db_set("status", "Completed", update_modified=False)
					self.flags.status_changed_to = "Completed"
					self.integration_request.db_set("output", payment.status, update_modified=False)

				case "cancelled" | "customer_approval_denied" | "charged_back":
					self.integration_request.db_set("status", "Cancelled", update_modified=False)
					self.integration_request.db_set("error", payment.status, update_modified=False)

				case _:
					self.integration_request.db_set("status", "Failed", update_modified=False)
					self.integration_request.db_set("error", payment.status, update_modified=False)

		except Exception as e:
			self.integration_request.db_set("error", str(e))
			frappe.log_error("GoCardless Payment Error", str(e))

		if self.flags.status_changed_to == "Completed":
			status = "Completed"
			if "reference_doctype" in self.data and "reference_docname" in self.data:
				custom_redirect_to = None
				try:
					custom_redirect_to = frappe.get_doc(
						self.data.get("reference_doctype"),
						self.data.get("reference_docname"),
					).run_method("on_payment_authorized", self.flags.status_changed_to)
				except Exception as e:
					frappe.log_error("Gocardless redirect failed", str(e))

				if custom_redirect_to:
					redirect_to = custom_redirect_to

			redirect_url = redirect_to
		else:
			status = "Error"
			redirect_url = "payment-failed"

			if redirect_message:
				redirect_url += "&" + urlencode({"redirect_message": redirect_message})

			redirect_url = get_url(redirect_url)

		return {"redirect_to": redirect_url, "status": status}

	@frappe.whitelist()
	def fetch_history(self, days):
		"""Enqueue a background replay of GoCardless events from the last ``days`` days.

		Each event is run through the same handlers that process live webhooks, so the
		fetch produces the same documents (Payment Entries, payout Journal Entries,
		mandate status updates) that healthy webhook delivery would have created.
		"""
		days = cint(days)
		if days <= 0:
			frappe.throw(_("Please enter a positive number of days."))

		job_id = f"gocardless_fetch_history::{self.name}"
		if is_job_enqueued(job_id):
			frappe.throw(_("A history fetch is already running for {0}.").format(self.name))

		run_now = bool(frappe.conf.developer_mode or frappe.in_test)
		if is_scheduler_inactive() and not run_now:
			frappe.throw(
				_("Scheduler is inactive. Please enable it to fetch GoCardless history."),
				title=_("Scheduler Inactive"),
			)

		frappe.enqueue_doc(
			self.doctype,
			self.name,
			"run_fetch_history",
			queue="long",
			timeout=3600,
			job_id=job_id,
			days=days,
			user=frappe.session.user,
			now=run_now,
		)
		return {"enqueued": True, "days": days}

	def run_fetch_history(self, days, user=None):
		"""Worker entry point: fetch events for the window and replay each one.

		Not whitelisted -- only reachable via the background job enqueued by
		:meth:`fetch_history`.
		"""
		from payments.payment_gateways.doctype.gocardless_settings import set_status

		self.initialize_client()

		since = (datetime.utcnow() - timedelta(days=cint(days))).strftime("%Y-%m-%dT%H:%M:%S.000Z")
		events = list(self.client.events.all(params={"created_at[gt]": since, "limit": 500}))

		# The API returns events newest-first; replay oldest-first so status
		# transitions land in the same order they would have via webhooks.
		events.sort(key=lambda event: event.attributes.get("created_at") or "")

		total = len(events)
		for index, event in enumerate(events, 1):
			attributes = event.attributes
			self._ensure_resource_metadata(attributes)
			try:
				set_status(attributes)
			except Exception:
				frappe.log_error(
					f"GoCardless Fetch History event error ({attributes.get('id')})",
					frappe.get_traceback(),
				)
			frappe.db.commit()

			if index % 10 == 0 or index == total:
				frappe.publish_realtime(
					"gocardless_fetch_history_progress",
					{"docname": self.name, "current": index, "total": total},
					user=user,
				)

		frappe.publish_realtime(
			"gocardless_fetch_history_done",
			{"docname": self.name, "total": total},
			user=user,
		)

	def _ensure_resource_metadata(self, event_attributes):
		"""Populate ``resource_metadata`` for payment events when the list API omits it.

		Webhook payloads carry ``resource_metadata`` (the resource's metadata), which
		:func:`set_payment_request_status` uses to map a payment back to its Payment
		Request. The events-list API may not include it, so backfill it from the
		payment's own metadata (set as ``reference_doctype``/``reference_document`` in
		:meth:`create_charge_on_gocardless`).
		"""
		if event_attributes.get("resource_metadata"):
			return
		if event_attributes.get("resource_type") != "payments":
			return
		payment_id = (event_attributes.get("links") or {}).get("payment")
		if not payment_id:
			return
		try:
			payment = self.client.payments.get(payment_id)
			event_attributes["resource_metadata"] = payment.metadata or {}
		except Exception:
			frappe.log_error(
				f"GoCardless Fetch History metadata lookup failed ({payment_id})",
				frappe.get_traceback(),
			)


def get_gateway_controller(doc):
	payment_request = frappe.get_doc("Payment Request", doc)
	gateway_controller = frappe.db.get_value(
		"Payment Gateway", payment_request.payment_gateway, "gateway_controller"
	)
	return gateway_controller


def gocardless_initialization(doc):
	gateway_controller = get_gateway_controller(doc)
	settings = frappe.get_doc("GoCardless Settings", gateway_controller)
	return settings.initialize_client()
