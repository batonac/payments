from . import __version__ as app_version

app_name = "payments"
app_title = "Payments"
app_publisher = "Frappe Technologies"
app_description = "Payments app for frappe"
app_email = "hello@frappe.io"
app_license = "MIT"
before_install = "payments.utils.before_install"
after_install = "payments.utils.make_custom_fields"
before_uninstall = "payments.utils.delete_custom_fields"
extend_doctype_class = {"Web Form": "payments.overrides.payment_webform.PaymentWebForm"}
scheduler_events = {
	"all": [
		"payments.payment_gateways.doctype.razorpay_settings.razorpay_settings.capture_payment",
	],
}
before_tests = "erpnext.setup.utils.before_tests"  
override_whitelisted_methods = {
	"frappe.website.doctype.web_form.web_form.accept": "payments.overrides.payment_webform.accept"
}
export_python_type_annotations = True
required_apps = ["erpnext"]