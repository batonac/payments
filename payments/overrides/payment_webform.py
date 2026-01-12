import json
from typing import Any, cast

import frappe
from frappe.core.doctype.file.utils import remove_file_by_url
from frappe.model.document import Document
from frappe.rate_limiter import rate_limit
from frappe.types import DF
from frappe.utils import flt, get_fullname, get_url
from frappe.website.doctype.web_form.web_form import WebForm

from payments.utils import get_payment_gateway_controller


class PaymentWebForm(WebForm):
	# Custom fields from web_form.json
	accept_payment: DF.Check | None
	amount: DF.Currency | None
	currency: DF.Link | None
	payment_gateway: DF.Link | None
	amount_based_on_field: DF.Check | None
	amount_field: DF.Data | None
	payer_name_based_on_field: DF.Check | None
	payer_name_field: DF.Data | None
	payer_email_based_on_field: DF.Check | None
	payer_email_field: DF.Data | None

	def validate(self):
		super().validate()

		if getattr(self, "accept_payment", False):
			self.validate_payment_amount()

	def validate_payment_amount(self) -> None:
		if self.amount_based_on_field and not self.amount_field:
			frappe.throw(frappe._("Please select a Amount Field."))
		elif not self.amount_based_on_field and not flt(self.amount) > 0:
			frappe.throw(frappe._("Amount must be greater than 0."))

	def get_payment_gateway_url(self, doc: Document) -> str:
		if getattr(self, "accept_payment", False):
			controller: Any = get_payment_gateway_controller(self.payment_gateway)
			if not controller:
				return get_url(self.success_url or self.route or "")

			title = f"Payment for {doc.doctype} {doc.name}"

			# Set Amount
			amount: Any = self.amount
			if self.amount_based_on_field and self.amount_field:
				amount = doc.get(self.amount_field)

			from decimal import Decimal

			if amount is None or Decimal(amount) <= 0:
				return get_url(self.success_url or self.route or "")

			# Set Payer Name
			payer_name: str = str(get_fullname(frappe.session.user) or "")
			if self.payer_name_based_on_field and self.payer_name_field:
				payer_name_value = doc.get(self.payer_name_field)
				if payer_name_value:
					payer_name = str(payer_name_value)

			# Set Payer Email
			payer_email: str = str(frappe.session.user or "")
			if self.payer_email_based_on_field and self.payer_email_field:
				payer_email_value = doc.get(self.payer_email_field)
				if payer_email_value:
					payer_email = str(payer_email_value)

			payment_details: dict[str, Any] = {
				"amount": amount,
				"title": title,
				"description": title,
				"reference_doctype": doc.doctype,
				"reference_docname": doc.name,
				"payer_email": payer_email,
				"payer_name": payer_name,
				"order_id": doc.name,
				"currency": self.currency,
				"payment_gateway": self.payment_gateway,
				"redirect_to": get_url(self.success_url or self.route or ""),
			}

			# Redirect the user to this url
			return str(controller.get_payment_url(**payment_details))

		return get_url(self.success_url or self.route or "")


@frappe.whitelist(allow_guest=True)
@rate_limit(key="web_form", limit=5, seconds=60, methods=["POST"])
def accept(
	web_form: str,
	data: str,
	docname: str | None = None,
	for_payment: bool | str = False,
) -> Document | str:
	"""Save the web form"""
	data_dict: frappe._dict = frappe._dict(json.loads(data))

	for_payment_bool: bool = bool(
		frappe.parse_json(for_payment) if isinstance(for_payment, str) else for_payment
	)

	docname = docname or data_dict.get("name")

	files: list[tuple[str, str]] = []
	files_to_delete: list[Any] = []

	web_form_doc: PaymentWebForm = cast(PaymentWebForm, frappe.get_lazy_doc("Web Form", web_form))

	if docname and not web_form_doc.allow_edit:
		frappe.throw(frappe._("You are not allowed to update this Web Form Document"))

	frappe.flags.in_web_form = True
	doctype_name: str = str(data_dict.get("doctype", ""))
	meta = frappe.get_meta(doctype_name)

	doc: Document
	if docname:
		# update
		doc = frappe.get_doc(doctype_name, docname)
	else:
		# insert
		doc = frappe.new_doc(doctype_name)

	# set values
	for field in web_form_doc.web_form_fields:
		fieldname: str = field.fieldname or ""
		if not fieldname:
			continue
		df = meta.get_field(fieldname)
		value: Any = data_dict.get(fieldname, None)

		if df and df.fieldtype in ("Attach", "Attach Image"):
			if value and isinstance(value, str) and "data:" in value and "base64" in value:
				files.append((fieldname, value))
				if not doc.name:
					doc.set(fieldname, "")
				continue

			elif not value and doc.get(fieldname):
				files_to_delete.append(doc.get(fieldname))

		doc.set(fieldname, value)

	if for_payment_bool:
		web_form_doc.validate_mandatory(doc)
		doc.run_method("validate_payment")
		doc.set("payment_gateway", web_form_doc.payment_gateway)

	if doc.name:
		if web_form_doc.has_web_form_permission(doc.doctype, doc.name, "write"):
			doc.save(ignore_permissions=True)
		else:
			# only if permissions are present
			doc.save()
	else:
		# insert
		if web_form_doc.login_required and frappe.session.user == "Guest":
			frappe.throw(frappe._("You must login to submit this form"))

		ignore_mandatory: bool = True if files else False
		doc.insert(ignore_permissions=True, ignore_mandatory=ignore_mandatory)

	# add files
	if files:
		for f in files:
			fieldname, filedata = f

			# remove earlier attached file (if exists)
			field_value = doc.get(fieldname)
			if field_value and isinstance(field_value, str):
				remove_file_by_url(field_value, doctype=doc.doctype, name=doc.name)

			# save new file
			filename, dataurl = filedata.split(",", 1)
			_file: Document = frappe.get_doc(
				{
					"doctype": "File",
					"file_name": filename,
					"attached_to_doctype": doc.doctype,
					"attached_to_name": doc.name,
					"content": dataurl,
					"decode": True,
				}
			)
			_file.save()

			# update values
			doc.set(fieldname, _file.get("file_url"))

		doc.save(ignore_permissions=True)

	if files_to_delete:
		for f in files_to_delete:
			if f and isinstance(f, str):
				remove_file_by_url(f, doctype=doc.doctype, name=doc.name)

	frappe.flags.web_form_doc = doc

	if for_payment_bool:
		return web_form_doc.get_payment_gateway_url(doc)
	else:
		return doc
