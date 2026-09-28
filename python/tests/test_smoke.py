import unittest

from ps_license_sdk import LicenseClient, LicenseError, machine_code, sign


class SmokeTest(unittest.TestCase):
    def test_machine_code_stable(self):
        self.assertEqual(machine_code(), machine_code())
        self.assertGreaterEqual(len(machine_code()), 8)

    def test_sign_deterministic(self):
        params = {"productUniqueCode": "PRO-2026-001", "machineCode": "M123", "edition": "PRO", "expiryDays": 0, "clientOrderId": "x", "licenseCode": "", "timestamp": 1000}
        self.assertEqual(sign("secret", params), sign("secret", params))

    def test_sign_binds_billing_period(self):
        base = {"productUniqueCode": "PRO-2026-001", "machineCode": "M123", "edition": "PRO", "expiryDays": 0, "clientOrderId": "x", "licenseCode": "LIC", "timestamp": 1000}
        monthly = sign("secret", {**base, "billingPeriod": "MONTHLY"})
        permanent = sign("secret", {**base, "billingPeriod": "PERMANENT"})
        # billingPeriod 必须进入签名串：仅周期不同 → 签名不同
        self.assertNotEqual(monthly, permanent)
        # 归一：strip + 大写
        self.assertEqual(sign("secret", {**base, "billingPeriod": " monthly "}), monthly)

    def test_purchase_url(self):
        url = LicenseClient(product_unique_code="PRO-2026-001").purchase_url("MABC")
        self.assertIn("productUniqueCode=PRO-2026-001", url)
        self.assertIn("machineCode=MABC", url)

    def test_check_update_posts_and_parses(self):
        captured = {}

        class FakeClient(LicenseClient):
            def request(self, path, body=None, signed=False, timeout=15.0):
                captured["path"] = path
                captured["body"] = body
                return {"hasUpdate": True, "latestVersion": "1.3.0"}

        result = FakeClient(product_unique_code="PRO-2026-001").check_update("1.2.0")
        self.assertEqual(captured["path"], "/product/updateCheck")
        self.assertEqual(captured["body"]["productUniqueCode"], "PRO-2026-001")
        self.assertEqual(captured["body"]["currentVersion"], "1.2.0")
        self.assertEqual(result, {"hasUpdate": True, "latestVersion": "1.3.0"})

    def test_check_update_requires_product_code(self):
        with self.assertRaises(LicenseError):
            LicenseClient().check_update("1.2.0")


if __name__ == "__main__":
    unittest.main()
