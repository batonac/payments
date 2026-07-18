# Copyright (c) 2018, Frappe Technologies and contributors
# For license information, please see license.txt


import hashlib
import hmac
import json
from typing import cast

import frappe
from dateutil import parser
from erpnext.accounts.doctype.payment_request.payment_request import PaymentRequest
from frappe.integrations.doctype.webhook.webhook import log_request
from frappe.utils import flt


@frappe.whitelist(allow_guest=True)
def webhooks():
	r = frappe.request
	if not r:
		return

	if not authenticate_signature(r):
		raise frappe.AuthenticationError

	gocardless_events = json.loads(r.get_data()) or []
	for event in gocardless_events["events"]:
		set_status(event)

	# log request
	log_request(
		webhook="",
		doctype="",
		docname="",
		url=r.url,
		headers=r.headers,
		data=gocardless_events,
	)

	# debug
	# frappe.log_error("GoCardless Webhook", str(gocardless_events))

	return 200


def set_status(event):
	resource_type = event.get("resource_type", {})
	reference_doctype = event.get("resource_metadata", {}).get("reference_doctype")

	if resource_type == "mandates":
		set_mandate_status(event)
	if resource_type == "payments" and reference_doctype == "Payment Request":
		set_payment_request_status(event)
	if resource_type == "payouts":
		if "erpnext" in frappe.get_installed_apps():
			create_payout_journal(event)


def set_mandate_status(event):
	mandates = []
	if isinstance(event["links"], list):
		for link in event["links"]:
			mandates.append(link["mandate"])
	else:
		mandates.append(event["links"]["mandate"])

	if (
		event["action"] == "pending_customer_approval"
		or event["action"] == "pending_submission"
		or event["action"] == "submitted"
		or event["action"] == "active"
	):
		disabled = 0
	else:
		disabled = 1

	for mandate in mandates:
		frappe.db.set_value("GoCardless Mandate", mandate, "disabled", disabled)


def set_payment_request_status(event):
	event_action = event.get("action")
	event_description = event.get("details", {}).get("description")
	payment_id = event.get("links", {}).get("payment")
	comment_email = "help@gocardless.com"
	comment = ""
	if event_action:
		comment += (
			f"<strong>GoCardless Event: <em>{event_action.replace('_', ' ').capitalize()}</em></strong>"
		)
	if event_description:
		comment += f"<br>{event_description}"
	if payment_id:
		comment += f"<br><a href='https://manage.gocardless.com/payments/{payment_id}'>View Payment</a>"
	payment_request = event.get("resource_metadata", {}).get("reference_document")
	if not payment_request:
		return
	doc = cast(PaymentRequest, frappe.get_doc("Payment Request", payment_request))
	if comment:
		doc.add_comment("Info", text=comment, comment_by="GoCardless", comment_email=comment_email).db_set(
			"subject", event_action
		)
		doc.db_update()
	if event_action == "submitted" and doc.status != "Initiated":
		doc.db_set("status", "Initiated")
	elif event_action in ["confirmed", "paid_out"] and doc.status != "Paid":
		part_amount = flt((event.get("resource_metadata") or {}).get("part_amount"))
		if part_amount and payment_id:
			# Per-payment settlement (cap-split and post-2026-07 single charges):
			# one Payment Entry per GoCardless payment, keyed by the payment id,
			# for exactly the charged amount. ERPNext maintains the Payment
			# Request outstanding/status (Partially Paid -> Paid) from the PE
			# references via update_payment_requests_as_per_pe_references.
			settle_gocardless_payment(doc, part_amount, payment_id, event)
		else:
			# Legacy payments (no part_amount metadata): the request may already
			# be settled by a Payment Entry created here previously
			# (reference_no == doc.name), or by one allocated to its reference
			# document elsewhere -- which drives outstanding_amount to 0. In
			# either case there is nothing left to pay; calling set_as_paid()
			# would build a zero-amount Payment Entry and fail with "Paid Amount
			# is mandatory". So just reflect the Paid status instead.
			payment_entry_exists = frappe.db.exists(
				"Payment Entry",
				{
					"reference_no": doc.name,
					"docstatus": 1,
				},
			)
			if payment_entry_exists or flt(doc.outstanding_amount) <= 0:
				doc.db_set("status", "Paid")
			else:
				# create payment entry
				try:
					# set session user to system user to avoid permission issues
					frappe.local.session.user = "Administrator"
					doc.set_as_paid()
					doc.db_set("status", "Paid")
				except Exception as e:
					frappe.log_error(
						f"GoCardless Payment Request {doc.name} set_as_paid error",
						{"error": str(e), "event": event},
					)
	elif event_action == "cancelled" and doc.status != "Cancelled":
		doc.set_as_cancelled()
	elif event_action == "failed" and doc.status != "Failed":
		doc.db_set("status", "Failed")
		try:  # failed reason is a field in ERPNext version 16+, so it may not exist in the database
			doc.db_set("failed_reason", event["details"]["description"])
		except KeyError:
			pass


def settle_gocardless_payment(doc: PaymentRequest, amount: float, payment_id: str, event=None):
	"""Create a submitted Payment Entry for one confirmed GoCardless payment.

	Used for charges carrying part_amount metadata (cap-split parts and
	post-split-deploy single charges). Idempotent per GoCardless payment id
	(stored as the Payment Entry reference_no). The amount is capped at the
	Payment Request's current outstanding so webhook replays and races cannot
	over-collect. Payment Request status (Partially Paid/Paid) is maintained by
	ERPNext from the payment-request-linked Payment Entry references.
	"""
	from erpnext.accounts.doctype.accounting_dimension.accounting_dimension import (
		get_accounting_dimensions,
	)
	from erpnext.accounts.doctype.payment_entry.payment_entry import get_payment_entry
	from frappe.utils import nowdate

	if frappe.db.exists("Payment Entry", {"reference_no": payment_id, "docstatus": 1}):
		return

	doc.load_from_db()
	amount = min(flt(amount), flt(doc.outstanding_amount))
	if amount <= 0:
		return

	try:
		# set session user to system user to avoid permission issues
		frappe.local.session.user = "Administrator"
		frappe.flags.ignore_account_permission = True

		payment_entry = get_payment_entry(
			doc.reference_doctype,
			doc.reference_name,
			party_amount=amount,
			bank_account=doc.payment_account,
			created_from_payment_request=True,
		)
		payment_entry.set_missing_ref_details(force=True)
		payment_entry.update(
			{
				"mode_of_payment": doc.mode_of_payment,
				"reference_no": payment_id,
				"reference_date": nowdate(),
				"remarks": (
					f"Payment Entry against {doc.reference_doctype} {doc.reference_name} "
					f"via Payment Request {doc.name} (GoCardless payment {payment_id})"
				),
			}
		)
		doc._allocate_payment_request_to_pe_references(references=payment_entry.references)
		payment_entry.update(
			{
				"cost_center": doc.get("cost_center"),
				"project": doc.get("project"),
			}
		)
		for dimension in get_accounting_dimensions():
			payment_entry.update({dimension: doc.get(dimension)})

		payment_entry.insert(ignore_permissions=True)
		payment_entry.submit()
	except Exception as e:
		frappe.log_error(
			f"GoCardless settlement failed for {doc.name} / payment {payment_id}",
			{"error": str(e), "event": event},
		)


def create_payout_journal(event):
	# Extract relevant data from the event
	payout_id = event.get("links").get("payout")
	# get the client
	gc_settings = frappe.get_last_doc("GoCardless Settings", filters={"use_sandbox": 0})
	client = gc_settings.initialize_client()
	payout = client.payouts.get(payout_id)
	print(f"Processing payout {payout_id} with reference {payout.reference}")
	if frappe.db.exists("Journal Entry", {"cheque_no": payout.reference}):
		return
	print(f"Creating journal entry for payout {payout_id}")
	try:
		# Get the internal payment account
		payment_gateway = frappe.get_value(
			"Payment Gateway", filters={"gateway_controller": gc_settings.name}, fieldname="name"
		)
		payment_account = frappe.get_value(
			"Payment Gateway Account",
			filters={"payment_gateway": payment_gateway},
			fieldname="payment_account",
		)

		# Get the internal deposit and fees accounts
		gc_bank_account = payout.links.creditor_bank_account
		account_number_ending = client.creditor_bank_accounts.get(gc_bank_account).attributes.get(
			"account_number_ending"
		)
		bank_account = frappe.get_last_doc(
			"Bank Account", filters={"bank_account_no": ["like", "%" + account_number_ending]}
		)
		deposit_account = bank_account.account
		fees_account = gc_settings.fees_account

		# Convert amounts to float
		amount = float(payout.amount) / 100
		deducted_fees = float(payout.deducted_fees) / 100

		# Parse the 'created_at' value and extract the date
		created_at_date = parser.parse(payout.created_at).date()

		# Create the journal entry
		journal_entry = frappe.get_doc(
			{
				"doctype": "Journal Entry",
				"voucher_type": "Journal Entry",
				"posting_date": payout.arrival_date,
				"cheque_date": created_at_date,
				"cheque_no": payout.reference,
				"accounts": [
					{
						"account": deposit_account,
						"debit_in_account_currency": amount,
						"debit": amount,
						"credit": 0,
						"credit_in_account_currency": 0,
					},
					{
						"account": fees_account,
						"debit_in_account_currency": deducted_fees,
						"debit": deducted_fees,
						"credit": 0,
						"credit_in_account_currency": 0,
					},
					{
						"account": payment_account,
						"debit_in_account_currency": 0,
						"debit": 0,
						"credit": amount + deducted_fees,
						"credit_in_account_currency": amount + deducted_fees,
					},
				],
			}
		)
		journal_entry.insert(ignore_permissions=True)
		journal_entry.submit()
	except Exception as e:
		# Log any exceptions that occur
		frappe.log_error("GoCardless Payout Journal Creation Error", str(e))


def authenticate_signature(r):
	"""Returns True if the received signature matches the generated signature"""
	received_signature = frappe.get_request_header("Webhook-Signature")

	if not received_signature:
		return False

	for key in get_webhook_keys():
		computed_signature = hmac.new(key.encode("utf-8"), r.get_data(), hashlib.sha256).hexdigest()
		if hmac.compare_digest(str(received_signature), computed_signature):
			return True

	return False


def get_webhook_keys():
	def _get_webhook_keys():
		webhook_keys = [
			d.webhooks_secret
			for d in frappe.get_all(
				"GoCardless Settings",
				fields=["webhooks_secret"],
			)
			if d.webhooks_secret
		]

		return webhook_keys

	return frappe.cache().get_value("gocardless_webhooks_secret", _get_webhook_keys)


def clear_cache():
	frappe.cache().delete_value("gocardless_webhooks_secret")
