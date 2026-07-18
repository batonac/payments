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
		alert_recipients: DF.SmallText | None
		fees_account: DF.Link | None
		gateway_name: DF.Data
		header_img: DF.AttachImage | None
		maximum_charge_amount: DF.Currency
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

	def on_payment_request_submission(self, payment_request):
		"""Attempt a direct-debit charge against the customer's mandate.

		Contract with erpnext's PaymentRequest.payment_gateway_validation:
		return False when the gateway handled payment (charge(s) created, no
		payment URL needed), True when the customer must act via the payment
		link (no valid mandate, or no charge could be created).

		Never raises: erpnext swallows exceptions from this hook silently
		(payment_request.py, payment_gateway_validation's bare except), which
		historically hid every failure — e.g. a TypeError from a string
		transaction_date suppressed the entire e-Billing auto-charge flow.
		Failures are logged and alerted here instead.

		The outcome is cached on the document's flags: the erpnext submit path
		(before_submit -> set_payment_request_url) re-invokes this hook on the
		same in-memory document after callers have already validated a draft,
		which used to create a second Integration Request + charge attempt per
		Payment Request (deduplicated only by the GoCardless Idempotency-Key).
		"""
		if payment_request.flags.get("gocardless_charge_attempted"):
			return payment_request.flags.get("gocardless_charge_result", True)

		try:
			result = self._initiate_mandate_charge(payment_request)
		except Exception:
			frappe.log_error("GoCardless auto-charge failed", frappe.get_traceback())
			self.notify_charge_failure(
				payment_request,
				"Automatic GoCardless charge failed with an unexpected error; "
				"see Error Log. The payment-link email flow applies instead.",
			)
			result = True

		payment_request.flags.gocardless_charge_attempted = True
		payment_request.flags.gocardless_charge_result = result
		return result

	def _initiate_mandate_charge(self, payment_request) -> bool:
		logger = frappe.logger("gocardless")

		customer_data = frappe._dict()
		if payment_request.reference_doctype != "Fees":
			customer_data = (
				frappe.db.get_value(
					payment_request.reference_doctype,
					payment_request.reference_name,
					["company", "customer_name"],
					as_dict=1,
				)
				or frappe._dict()
			)

		amount = flt(payment_request.grand_total, payment_request.precision("grand_total"))
		# getdate() coercion: desk-submitted documents carry string dates, and
		# max(str, date) below raises TypeError otherwise
		charge_date = (
			frappe.utils.getdate(payment_request.transaction_date)
			if payment_request.get("transaction_date")
			else frappe.utils.getdate()
		)

		data = {
			"amount": amount,
			"title": customer_data.company,
			"description": payment_request.subject,
			"reference_doctype": payment_request.doctype,
			"reference_docname": payment_request.name,
			"payer_email": payment_request.email_to or frappe.session.user,
			"payer_name": customer_data.customer_name,
			"order_id": payment_request.name,
			"currency": payment_request.currency,
			"charge_date": charge_date,
		}

		valid_mandate, next_possible_charge_date = self.check_mandate_validity(data)
		if valid_mandate is None:
			logger.info(f"No valid mandate for {data.get('payer_name')}; using payment-link flow")
			return True

		data.update(valid_mandate)
		data["charge_date"] = str(max(charge_date, frappe.utils.getdate(next_possible_charge_date)))

		# Cross-request idempotency: a charge for this Payment Request is already
		# queued or through ("Failed" deliberately excluded so Re-Initiate Charge
		# can retry after a failure).
		if frappe.db.exists(
			"Integration Request",
			{
				"integration_request_service": "GoCardless",
				"reference_doctype": "Payment Request",
				"reference_docname": payment_request.name,
				"status": ("in", ("Queued", "Authorized", "Completed")),
			},
		):
			logger.info(f"Charge already initiated for {payment_request.name}; skipping")
			return False

		parts = self.get_charge_parts(amount)
		succeeded, failed = [], []
		for index, part_amount in enumerate(parts, start=1):
			part = dict(data)
			part["amount"] = part_amount
			if len(parts) > 1:
				part["idempotency_key"] = f"{payment_request.name}:{index}"
				part["description"] = f"{payment_request.subject} ({index} of {len(parts)})"
				part["part"] = f"{index}/{len(parts)}"
			else:
				part["idempotency_key"] = payment_request.name

			outcome = self.create_payment_request(part) or {}
			(succeeded if outcome.get("status") == "Completed" else failed).append((index, part_amount))

		if len(parts) > 1:
			payment_request.add_comment(
				"Info",
				text=(
					f"GoCardless charge split into {len(parts)} payments of at most "
					f"{flt(self.get('maximum_charge_amount'))} ({payment_request.currency}) "
					f"due to the per-transaction cap. "
					f"Created: {len(succeeded)}, failed: {len(failed)}."
				),
			)

		if failed:
			self.notify_charge_failure(
				payment_request,
				f"GoCardless charge failed for part(s) {[i for i, _ in failed]} "
				f"of {len(parts)} (amounts: {[a for _, a in failed]}). "
				"See the linked Integration Requests / Error Log; use Re-Initiate "
				"Charge after resolving.",
			)

		# If anything was charged, the gateway is handling (part of) the payment:
		# suppress the payment-link flow to avoid double collection and let the
		# failure alert drive manual follow-up for the remainder. Only when
		# nothing was charged fall back to the payment link.
		return not succeeded

	def get_charge_parts(self, amount: float) -> list[float]:
		"""Split an amount into per-transaction-cap-sized parts (auto-split)."""
		cap = flt(self.get("maximum_charge_amount"))
		amount = flt(amount)
		if not cap or amount <= cap:
			return [amount] if amount else []

		parts = []
		remaining = amount
		while remaining > cap:
			parts.append(cap)
			remaining = flt(remaining - cap, 2)
		if remaining > 0:
			parts.append(remaining)
		return parts

	def notify_charge_failure(self, payment_request, message: str):
		try:
			payment_request.add_comment("Info", text=message)
		except Exception:
			frappe.log_error("GoCardless: failed to add failure comment", frappe.get_traceback())

		recipients = [
			address.strip() for address in (self.get("alert_recipients") or "").split(",") if address.strip()
		]
		if not recipients:
			return
		try:
			frappe.sendmail(
				recipients=recipients,
				subject=f"GoCardless auto-charge issue: {payment_request.name}",
				message=(
					f"{message}<br><br>Payment Request: {payment_request.name}<br>"
					f"Reference: {payment_request.reference_doctype} "
					f"{payment_request.reference_name}<br>"
					f"Amount: {payment_request.grand_total} {payment_request.currency}"
				),
			)
		except Exception:
			frappe.log_error("GoCardless: failed to send failure alert", frappe.get_traceback())

	def check_mandate_validity(self, data):
		"""Return ({"mandate": id}, next_possible_charge_date) for the newest
		valid enabled mandate of the customer, or (None, None).

		Iterates newest-first and disables only the specific mandates the API
		reports as invalid (the previous dict-filter set_value disabled ALL of
		the customer's enabled mandates at once).
		"""
		mandate_names = frappe.get_all(
			"GoCardless Mandate",
			filters={"customer": data.get("payer_name"), "disabled": 0},
			order_by="creation desc",
			pluck="mandate",
		)
		if not mandate_names:
			return None, None

		invalid_statuses = [
			"blocked",
			"cancelled",
			"consumed",
			"expired",
			"failed",
			"suspended_by_payer",
		]

		self.initialize_client()
		for mandate_name in mandate_names:
			try:
				mandate = self.client.mandates.get(mandate_name)
			except gocardless_pro.errors.GoCardlessProError as e:
				# e.g. "Resource not found": the mandate does not exist on this
				# GoCardless account (stale/imported reference) — treat as
				# invalid and fall through to the next mandate
				frappe.logger("gocardless").warning(f"Mandate {mandate_name} lookup failed ({e}); disabling")
				frappe.db.set_value("GoCardless Mandate", {"mandate": mandate_name}, "disabled", 1)
				continue
			if mandate.status in invalid_statuses:
				frappe.db.set_value("GoCardless Mandate", {"mandate": mandate_name}, "disabled", 1)
				continue
			return {"mandate": mandate_name}, mandate.next_possible_charge_date

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
		# reset per-charge outcome state: the same settings doc handles multiple
		# split parts in one request, and a stale "Completed" from an earlier
		# part would mask a later part's failure
		self.flags.status_changed_to = None

		redirect_to = self.data.get("redirect_to") or None
		redirect_message = self.data.get("redirect_message") or None

		reference_doc = frappe.get_doc(self.data.get("reference_doctype"), self.data.get("reference_docname"))
		self.initialize_client()

		# round() before cint(): bare cint(x * 100) truncates float error
		# (105.86 * 100 = 10585.999... -> 10585, one cent short)
		charge_amount = flt(self.data.get("amount") or reference_doc.grand_total)
		metadata = {
			"reference_doctype": reference_doc.doctype,
			"reference_document": reference_doc.name,
		}
		if self.data.get("amount"):
			# lets the webhook create a per-payment Payment Entry for exactly
			# this amount (required for cap-split charges)
			metadata["part_amount"] = str(charge_amount)

		try:
			payment = self.client.payments.create(
				params={
					"amount": cint(round(charge_amount * 100)),
					"charge_date": self.data.get("charge_date"),
					"currency": reference_doc.currency,
					"links": {"mandate": self.data.get("mandate")},
					"metadata": metadata,
				},
				headers={
					"Idempotency-Key": self.data.get("idempotency_key") or self.data.get("reference_docname"),
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
			# status must leave "Queued", or failed charges look forever in-flight
			# (and block the cross-request idempotency guard from retrying)
			self.integration_request.db_set("status", "Failed", update_modified=False)
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
			queue="default",
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
