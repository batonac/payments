import frappe


def execute():
	"""`customer` is a standard field of GoCardless Mandate. Sites installed before it was
	added to the DocType JSON also hold a Custom Field of the same name, which shadows it."""
	frappe.db.delete("Custom Field", {"dt": "GoCardless Mandate", "fieldname": "customer"})
	frappe.clear_cache(doctype="GoCardless Mandate")
