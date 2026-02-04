# Copyright (c) 2018, Frappe Technologies and Contributors
# License: MIT. See LICENSE
import unittest
from typing import cast

import frappe
from frappe.tests.classes import IntegrationTestCase

from .stripe_settings import StripeSettings

# Stripe's pre-defined test tokens - these map to test cards without requiring raw card data
# See: https://stripe.com/docs/testing#tokens
TEST_TOKEN_VISA = "tok_visa"  # Maps to 4242424242424242


def get_test_stripe_settings():
	"""Get a Stripe Settings document configured with test keys, if available."""
	stripe_settings_list = frappe.get_all(
		"Stripe Settings",
		filters={"publishable_key": ["like", "pk_test_%"]},
		pluck="name",
		limit=1,
	)
	if stripe_settings_list:
		return cast(StripeSettings, frappe.get_doc("Stripe Settings", stripe_settings_list[0]))
	return None


class TestStripeSettings(IntegrationTestCase):
	"""Test cases for Stripe Settings - only runs if test Stripe credentials are configured."""

	stripe_settings = None

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		cls.stripe_settings = get_test_stripe_settings()
		if not cls.stripe_settings:
			raise unittest.SkipTest(
				"No Stripe Settings with test keys (pk_test_*) found. Skipping Stripe tests."
			)

	def test_stripe_charge_with_metadata(self):
		"""Test that a Stripe charge can be created with metadata."""
		import stripe

		# assert that the stripe settings exists and have the test keys
		self.assertIsNotNone(self.stripe_settings, "Stripe Settings with test keys should exist")
		assert self.stripe_settings is not None  # Type narrowing for type checker
		self.assertTrue(
			self.stripe_settings.publishable_key.startswith("pk_test_"),
			"Publishable key should be a test key starting with 'pk_test_'",
		)

		# Prepare test data using Stripe's pre-defined test token
		test_data = {
			"amount": 1.00,  # $1.00 - minimum for testing
			"currency": "USD",
			"stripe_token_id": TEST_TOKEN_VISA,
			"description": "Test charge from automated test suite",
			"payer_email": "test@example.com",
			"reference_doctype": "Test Doctype",
			"reference_docname": "TEST-DOC-001",
		}

		# Set up stripe API key
		stripe.api_key = self.stripe_settings.get_password(fieldname="secret_key", raise_exception=False)

		# Create the charge directly using stripe API to verify metadata works
		charge = stripe.Charge.create(
			amount=100,  # Amount in cents
			currency=test_data["currency"],
			source=test_data["stripe_token_id"],
			description=test_data["description"],
			receipt_email=test_data["payer_email"],
			metadata={
				"reference_doctype": test_data["reference_doctype"],
				"reference_docname": test_data["reference_docname"],
			},
		)

		# Verify the charge was successful
		self.assertTrue(charge.captured, "Charge should be captured")
		self.assertEqual(charge.status, "succeeded", "Charge status should be 'succeeded'")
		self.assertEqual(charge.amount, 100, "Charge amount should be 100 cents")
		self.assertEqual(charge.currency, "usd", "Charge currency should be USD")

		# Verify metadata was logged correctly
		self.assertIsNotNone(charge.metadata, "Charge should have metadata")
		self.assertEqual(
			charge.metadata.get("reference_doctype"),
			"Test Doctype",
			"Metadata should contain reference_doctype",
		)
		self.assertEqual(
			charge.metadata.get("reference_docname"),
			"TEST-DOC-001",
			"Metadata should contain reference_docname",
		)

	def test_stripe_settings_create_request_with_metadata(self):
		"""Test that StripeSettings.create_request() includes metadata in the charge."""
		import stripe

		# assert that the stripe settings exists and have the test keys
		self.assertIsNotNone(self.stripe_settings, "Stripe Settings with test keys should exist")
		assert self.stripe_settings is not None  # Type narrowing for type checker
		self.assertTrue(
			self.stripe_settings.publishable_key.startswith("pk_test_"),
			"Publishable key should be a test key starting with 'pk_test_'",
		)

		# Prepare test data matching what would come from stripe_checkout
		# Using Stripe's pre-defined test token
		test_data = frappe._dict(
			{
				"amount": 1.50,
				"currency": "USD",
				"stripe_token_id": TEST_TOKEN_VISA,
				"description": "Test payment via create_charge_on_stripe",
				"payer_email": "test@example.com",
				"reference_doctype": "Player Application",
				"reference_docname": "TEST-APP-002",
			}
		)

		# Set up stripe API key and data on the settings object
		# This mimics what create_request does before calling create_charge_on_stripe
		stripe.api_key = self.stripe_settings.get_password(fieldname="secret_key", raise_exception=False)
		self.stripe_settings.data = test_data

		# Create a mock integration_request to avoid database dependencies
		from unittest.mock import MagicMock

		self.stripe_settings.integration_request = MagicMock()
		self.stripe_settings.integration_request.status = "Queued"

		# Call create_charge_on_stripe directly (bypasses integration request log creation)
		self.stripe_settings.create_charge_on_stripe()

		# Verify the charge was created with correct metadata by fetching recent charges
		charges = stripe.Charge.list(limit=10)
		test_charge = None
		for charge in charges.data:
			# Find by description since we know this is unique for this test
			if charge.description == "Test payment via create_charge_on_stripe" and charge.amount == 150:
				test_charge = charge
				break

		self.assertIsNotNone(test_charge, "Should find the test charge by description")
		assert test_charge is not None  # Type narrowing for type checker

		# Now verify metadata was logged correctly
		self.assertIsNotNone(test_charge.metadata, "Charge should have metadata")
		self.assertEqual(
			test_charge.metadata.get("reference_doctype"),
			"Player Application",
			f"Metadata should contain reference_doctype, got: {dict(test_charge.metadata)}",
		)
		self.assertEqual(
			test_charge.metadata.get("reference_docname"),
			"TEST-APP-002",
			f"Metadata should contain reference_docname, got: {dict(test_charge.metadata)}",
		)
		self.assertTrue(test_charge.captured, "Charge should be captured")

	def test_stripe_charge_minimum_amount(self):
		"""Test that the minimum charge amount validation works."""

		# assert that the stripe settings exists and have the test keys
		self.assertIsNotNone(self.stripe_settings, "Stripe Settings with test keys should exist")
		assert self.stripe_settings is not None  # Type narrowing for type checker
		# USD minimum is $0.50
		self.stripe_settings.validate_minimum_transaction_amount("USD", 0.50)

		# Should raise for amounts below minimum
		with self.assertRaises(frappe.ValidationError):
			self.stripe_settings.validate_minimum_transaction_amount("USD", 0.40)

	def test_stripe_supported_currency(self):
		"""Test currency validation."""

		# assert that the stripe settings exists and have the test keys
		self.assertIsNotNone(self.stripe_settings, "Stripe Settings with test keys should exist")
		assert self.stripe_settings is not None  # Type narrowing for type checker
		# Should not raise for supported currency
		self.stripe_settings.validate_transaction_currency("USD")

		# Should raise for unsupported currency
		with self.assertRaises(frappe.ValidationError):
			self.stripe_settings.validate_transaction_currency("XYZ")
