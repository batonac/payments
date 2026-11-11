# Copyright (c) 2018, Frappe Technologies and Contributors
# See license.txt

import frappe

from payments.patches.remove_gocardless_mandate_customer_custom_field import execute
from payments.tests.utils import PaymentsTestSuite
from payments.utils import make_custom_fields


class TestGoCardlessMandate(PaymentsTestSuite):
	def test_customer_is_a_standard_field(self):
		meta = frappe.get_meta("GoCardless Mandate", cached=False)
		self.assertEqual(len(meta.get("fields", {"fieldname": "customer"})), 1)
		self.assertFalse(meta.get_field("customer").get("is_custom_field"))

	def test_install_hook_does_not_redefine_customer(self):
		# a fresh install runs this hook after the DocType is synced
		make_custom_fields()
		self.assertFalse(
			frappe.db.exists("Custom Field", {"dt": "GoCardless Mandate", "fieldname": "customer"})
		)

	def test_patch_removes_the_legacy_custom_field(self):
		# sites installed before the DocType declared `customer` still hold the Custom Field
		legacy = frappe.get_doc(
			{
				"doctype": "Custom Field",
				"dt": "GoCardless Mandate",
				"fieldname": "customer",
				"fieldtype": "Link",
				"label": "Customer",
				"options": "Customer",
				"reqd": 1,
			}
		)
		legacy.flags.ignore_validate = True
		legacy.insert()

		execute()

		self.assertFalse(
			frappe.db.exists("Custom Field", {"dt": "GoCardless Mandate", "fieldname": "customer"})
		)
		meta = frappe.get_meta("GoCardless Mandate", cached=False)
		self.assertEqual(len(meta.get("fields", {"fieldname": "customer"})), 1)
		self.assertTrue(frappe.db.has_column("GoCardless Mandate", "customer"))
