# Copyright (c) 2018, Frappe Technologies and contributors
# For license information, please see license.txt


import hashlib
import hmac
import json

import frappe
from dateutil import parser


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

	# debug
	frappe.log_error("GoCardless Webhook", str(gocardless_events))

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
	if isinstance(event["links"], (list,)):
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
		comment += f"<strong>GoCardless Event: <em>{event_action.capitalize()}<em></strong>"
	if event_description:
		comment += f"<br>{event_description}"
	if payment_id:
		comment += f"<br><a href='https://manage.gocardless.com/payments/{payment_id}'>View Payment</a>"
	payment_request = event.get("resource_metadata", {}).get("reference_document")
	if not payment_request:
		return
	doc = frappe.get_doc("Payment Request", payment_request)
	if comment:
		doc.add_comment('Info', text=comment, comment_by="GoCardless", comment_email=comment_email)
	if event_action == "submitted" and doc.status != "Initiated":
		doc.db_set("status", "Initiated")
	if event_action == "confirmed" and doc.status != "Paid":
		doc.set_as_paid()
	if event_action == "cancelled" and doc.status != "Cancelled":
		doc.set_as_cancelled()
	if event_action == "failed" and doc.status != "Failed":
		doc.db_set("status", "Failed")
		try: # failed reason is a field in ERPNext version 16+, so it may not exist in the database
			doc.db_set("failed_reason", event["details"]["description"])
		except KeyError:
			pass


def create_payout_journal(event):
    try:
        # Extract relevant data from the event
        payout_id = event.get("links").get("payout")
        
        # Get the internal payment account
        gc_settings = frappe.get_last_doc("GoCardless Settings", filters={"use_sandbox": 0})
        payment_gateway = frappe.get_value("Payment Gateway", filters={"gateway_controller": gc_settings.name}, fieldname="name")
        payment_account = frappe.get_value("Payment Gateway Account", filters={"payment_gateway": payment_gateway}, fieldname="payment_account")
        
        # Get the internal deposit and fees accounts
        client = gc_settings.initialize_client()
        payout = client.payouts.get(payout_id)
        gc_bank_account = payout.links.creditor_bank_account
        account_number_ending = client.creditor_bank_accounts.get(gc_bank_account).attributes.get("account_number_ending")
        bank_account = frappe.get_last_doc("Bank Account", filters={"bank_account_no": ["like", "%" + account_number_ending]})
        deposit_account = bank_account.account
        fees_account = gc_settings.fees_account
        
        # Convert amounts to float
        amount = float(payout.amount) / 100
        deducted_fees = float(payout.deducted_fees) / 100

		# Parse the 'created_at' value and extract the date
        created_at_date = parser.parse(payout.created_at).date()
        
        # Create the journal entry
        journal_entry = frappe.get_doc({
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
                    "credit_in_account_currency": 0
                },
                {
                    "account": fees_account,
                    "debit_in_account_currency": 0,
                    "debit": 0,
                    "credit": deducted_fees,
                    "credit_in_account_currency": deducted_fees
                },
                {
                    "account": payment_account,
                    "debit_in_account_currency": 0,
                    "debit": 0,
                    "credit": amount + deducted_fees,
                    "credit_in_account_currency": amount + deducted_fees
                }
            ]
        })
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
