"""PowerSoftware 授权客户端（激活/校验/解绑/软件内发码升级/试用领取）"""

import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from .machine import machine_code

DEFAULT_BASE_URL = "https://www.powersoftware.app/frontApi"
VERIFY_CACHE_TTL_MS = 60 * 1000


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def sign(api_secret: str, params: dict) -> str:
    """HMAC 签名：productUniqueCode \\n machineCode \\n edition \\n expiryDays \\n clientOrderId \\n licenseCode \\n billingPeriod \\n timestamp
    billingPeriod 归一为 strip + 大写（缺省/generate 为空串），与其他语言 SDK 及服务端逐字节一致。"""
    payload = "\n".join(
        [
            str(params.get("productUniqueCode", "")),
            str(params.get("machineCode", "")),
            str(params.get("edition", "")),
            str(params.get("expiryDays", 0)),
            str(params.get("clientOrderId", "")),
            str(params.get("licenseCode", "")),
            str(params.get("billingPeriod") or "").strip().upper(),
            str(params.get("timestamp", "")),
        ]
    )
    return _b64url(hmac.new(api_secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest())


class LicenseError(RuntimeError):
    def __init__(self, message: str, error_code: str = "REQUEST_FAILED"):
        super().__init__(message)
        self.error_code = error_code


class LicenseClient:
    def __init__(self, base_url: str = DEFAULT_BASE_URL, api_secret: str = "", product_unique_code: str = None, cache_ttl_ms: int = VERIFY_CACHE_TTL_MS):
        self.base_url = base_url.rstrip("/")
        self.api_secret = api_secret
        self.product_unique_code = product_unique_code
        self.cache_ttl_ms = cache_ttl_ms
        self._verify_cache = None

    def request(self, path: str, body: dict = None, signed: bool = False, timeout: float = 15.0):
        payload = dict(body or {})
        if signed:
            payload["timestamp"] = int(time.time() * 1000)
            payload["signature"] = sign(self.api_secret, payload)
        req = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                data = json.loads(exc.read().decode("utf-8"))
            except Exception:
                data = {}
        except Exception as exc:  # 网络/超时
            raise LicenseError(str(exc), "NETWORK_ERROR") from exc
        if not data.get("success"):
            raise LicenseError(data.get("tip") or "request failed", data.get("code") or "REQUEST_FAILED")
        return data.get("content")

    def activate(self, license_code: str, machine_code_value: str = None):
        return self.request("/license/activate", {"licenseCode": license_code, "machineCode": machine_code_value or machine_code()})

    def verify(self, license_code: str, machine_code_value: str = None, activation_token: str = ""):
        return self.request(
            "/license/verify",
            {"licenseCode": license_code, "machineCode": machine_code_value or machine_code(), "activationToken": activation_token},
        )

    def deactivate(self, license_code: str, machine_code_value: str = None):
        return self.request("/license/deactivate", {"licenseCode": license_code, "machineCode": machine_code_value or machine_code()})

    def claim_trial(self, machine_code_value: str = None):
        if not self.product_unique_code:
            raise LicenseError("productUniqueCode required", "PRODUCT_ID_REQUIRED")
        return self.request("/license/trial/claim", {"productUniqueCode": self.product_unique_code, "machineCode": machine_code_value or machine_code()})

    def check_update(self, current_version: str):
        """检查版本更新：返回 { hasUpdate, latestVersion }。
        hasUpdate=true 时自行引导用户到产品详情页下载新版本；网络失败由调用方静默降级。"""
        if not self.product_unique_code:
            raise LicenseError("productUniqueCode required", "PRODUCT_ID_REQUIRED")
        return self.request("/product/updateCheck", {"productUniqueCode": self.product_unique_code, "currentVersion": current_version})

    def generate_for_software(self, machine_code_value: str, edition: str = "", expiry_days: int = 0, client_order_id: str = ""):
        if not self.product_unique_code:
            raise LicenseError("productUniqueCode required", "PRODUCT_ID_REQUIRED")
        return self.request(
            "/license/software/generate",
            {
                "productUniqueCode": self.product_unique_code,
                "machineCode": machine_code_value or machine_code(),
                "edition": edition,
                "expiryDays": expiry_days,
                "clientOrderId": client_order_id,
            },
            signed=True,
        )

    def upgrade_for_software(self, license_code: str, edition: str, machine_code_value: str = None, expiry_days: int = 0, client_order_id: str = "", billing_period: str = None):
        """软件内升级/续费。billing_period：目标计费周期（同版本多周期产品指定升级到哪条，缺省取该版本配置首行）。"""
        if not self.product_unique_code:
            raise LicenseError("productUniqueCode required", "PRODUCT_ID_REQUIRED")
        return self.request(
            "/license/software/upgrade",
            {
                "productUniqueCode": self.product_unique_code,
                "licenseCode": license_code,
                "machineCode": machine_code_value or machine_code(),
                "edition": edition,
                "expiryDays": expiry_days,
                "billingPeriod": billing_period,
                "clientOrderId": client_order_id,
            },
            signed=True,
        )

    def verify_cached(self, license_code: str, machine_code_value: str = None, activation_token: str = ""):
        now = int(time.time() * 1000)
        cache = self._verify_cache
        if cache and now - cache["at"] < self.cache_ttl_ms:
            return cache["data"]
        data = self.verify(license_code, machine_code_value, activation_token)
        self._verify_cache = {"at": now, "data": data}
        return data

    def purchase_url(self, machine_code_value: str = None, base: str = "https://www.powersoftware.app") -> str:
        """付费功能未授权时的购买页跳转 URL。"""
        if not self.product_unique_code:
            raise LicenseError("productUniqueCode required", "PRODUCT_ID_REQUIRED")
        params = {"productUniqueCode": self.product_unique_code, "machineCode": machine_code_value or machine_code()}
        return f"{base}/product/license/purchase?{urllib.parse.urlencode(params)}"
