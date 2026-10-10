package com.powersoftware.sdk;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * PowerSoftware 授权客户端（Java 8+，零依赖）。
 * 方法：activate / verify / deactivate / claimTrial / generateForSoftware / upgradeForSoftware / verifyCached / purchaseUrl。
 */
public class LicenseClient {

    public static final String DEFAULT_BASE_URL = "https://www.powersoftware.app/frontApi";
    private static final long VERIFY_CACHE_TTL_MS = 60_000L;

    private final String baseUrl;
    private final String apiSecret;
    private final String productUniqueCode;
    private final long cacheTtlMs;
    private VerifyCacheEntry verifyCache;

    public LicenseClient(String productUniqueCode, String apiSecret) {
        this(DEFAULT_BASE_URL, productUniqueCode, apiSecret, VERIFY_CACHE_TTL_MS);
    }

    public LicenseClient(String baseUrl, String productUniqueCode, String apiSecret) {
        this(baseUrl, productUniqueCode, apiSecret, VERIFY_CACHE_TTL_MS);
    }

    public LicenseClient(String baseUrl, String productUniqueCode, String apiSecret, long cacheTtlMs) {
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.productUniqueCode = productUniqueCode;
        this.apiSecret = apiSecret == null ? "" : apiSecret;
        this.cacheTtlMs = cacheTtlMs;
    }

    public static String machineCode() {
        return MachineCode.get();
    }

    /** HMAC 签名：productUniqueCode \\n machineCode \\n edition \\n expiryDays \\n clientOrderId \\n licenseCode \\n billingPeriod \\n timestamp（billingPeriod 归一 trim+大写，缺省/generate 为空串） */
    public static String sign(String apiSecret, Map<String, Object> params) {
        String billingPeriod = params.get("billingPeriod") == null ? "" : String.valueOf(params.get("billingPeriod")).trim().toUpperCase();
        String payload = String.join("\n",
                str(params.get("productUniqueCode")),
                str(params.get("machineCode")),
                str(params.get("edition")),
                params.get("expiryDays") == null ? "0" : String.valueOf(params.get("expiryDays")),
                str(params.get("clientOrderId")),
                str(params.get("licenseCode")),
                billingPeriod,
                str(params.get("timestamp")));
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(apiSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC unavailable", e);
        }
    }

    private static String str(Object v) {
        return v == null ? "" : String.valueOf(v);
    }

    /** addQuota 专用 HMAC 签名：productUniqueCode \n licenseCode \n addAmount \n quotaType \n clientOrderId \n edition \n timestamp（quotaType 归一 trim+大写，缺省 QUOTA；edition 缺省空串）*/
    public static String signAddQuota(String apiSecret, Map<String, Object> params) {
        String quotaType = params.get("quotaType") == null ? "QUOTA" : String.valueOf(params.get("quotaType")).trim().toUpperCase();
        String edition = params.get("edition") == null ? "" : String.valueOf(params.get("edition")).trim();
        String payload = String.join("\n",
                str(params.get("productUniqueCode")),
                str(params.get("licenseCode")),
                params.get("addAmount") == null ? "0" : String.valueOf(params.get("addAmount")),
                quotaType,
                str(params.get("clientOrderId")),
                edition,
                str(params.get("timestamp")));
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(apiSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC unavailable", e);
        }
    }

    /**
     * 非平台代收：给 QUOTA 额度码累加额度（HMAC 签名，走 addQuota 专用签名串）。
     * quotaType: "trial" 累加试用额度 trialCount（不改版本）| "quota"（默认）累加付费额度 quotaAmount。
     * edition（仅 quota）：加额度同时把码转到该付费版本；clientOrderId：审计/追溯（平台不做订单级幂等，重复发放由调用方去重）。
     */
    public Map<String, Object> addQuotaForSoftware(String licenseCode, int addAmount, String quotaType, String edition, String clientOrderId) throws Exception {
        requireProductCode();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("productUniqueCode", productUniqueCode);
        body.put("licenseCode", licenseCode);
        body.put("addAmount", addAmount);
        body.put("quotaType", quotaType == null ? "quota" : quotaType);
        if (edition != null) body.put("edition", edition);
        if (clientOrderId != null) body.put("clientOrderId", clientOrderId);
        body.put("timestamp", System.currentTimeMillis());
        body.put("signature", signAddQuota(apiSecret, body));
        return request("/license/software/addQuota", body, false);
    }

    /** 重载：仅指定额度类型（trial/quota），无 edition/订单号 */
    public Map<String, Object> addQuotaForSoftware(String licenseCode, int addAmount, String quotaType) throws Exception {
        return addQuotaForSoftware(licenseCode, addAmount, quotaType, null, null);
    }

    private static Map<String, Object> mapOf(Object... kvs) {
        Map<String, Object> m = new LinkedHashMap<String, Object>();
        for (int i = 0; i < kvs.length; i += 2) {
            m.put(String.valueOf(kvs[i]), kvs[i + 1]);
        }
        return m;
    }

    public Map<String, Object> request(String path, Map<String, Object> body, boolean signed) throws Exception {
        Map<String, Object> payload = new LinkedHashMap<String, Object>(body == null ? new LinkedHashMap<String, Object>() : body);
        if (signed) {
            payload.put("timestamp", System.currentTimeMillis());
            payload.put("signature", sign(apiSecret, payload));
        }
        byte[] jsonBytes = Json.stringify(payload).getBytes(StandardCharsets.UTF_8);
        HttpURLConnection conn = (HttpURLConnection) new URL(baseUrl + path).openConnection();
        conn.setRequestMethod("POST");
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(15000);
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(jsonBytes);
        }
        int code = conn.getResponseCode();
        String respBody;
        try (InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream()) {
            respBody = readAll(is);
        }
        conn.disconnect();
        Map<String, Object> json;
        try {
            json = Json.parseObject(respBody);
        } catch (Exception e) {
            throw new LicenseException("invalid response", "BAD_RESPONSE");
        }
        if (!Boolean.TRUE.equals(json.get("success"))) {
            String tip = json.get("tip") == null ? "request failed" : String.valueOf(json.get("tip"));
            String errorCode = json.get("code") == null ? "REQUEST_FAILED" : String.valueOf(json.get("code"));
            throw new LicenseException(tip, errorCode);
        }
        return (Map<String, Object>) json.get("content");
    }

    private static String readAll(InputStream is) throws Exception {
        if (is == null) {
            return "";
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) != -1) {
            out.write(buf, 0, n);
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    public Map<String, Object> activate(String licenseCode, String machineCodeValue) throws Exception {
        return request("/license/activate", mapOf("licenseCode", licenseCode, "machineCode", machineCodeValue), false);
    }

    public Map<String, Object> verify(String licenseCode, String machineCodeValue, String activationToken) throws Exception {
        return request("/license/verify", mapOf(
                "licenseCode", licenseCode,
                "machineCode", machineCodeValue,
                "activationToken", activationToken == null ? "" : activationToken), false);
    }

    public Map<String, Object> deactivate(String licenseCode, String machineCodeValue) throws Exception {
        return request("/license/deactivate", mapOf("licenseCode", licenseCode, "machineCode", machineCodeValue), false);
    }

    public Map<String, Object> claimTrial(String machineCodeValue) throws Exception {
        requireProductCode();
        return request("/license/trial/claim", mapOf("productUniqueCode", productUniqueCode, "machineCode", machineCodeValue), false);
    }

    /**
     * 检查版本更新：返回 { hasUpdate, latestVersion }。
     * hasUpdate=true 时自行引导用户到产品详情页下载新版本；网络失败由调用方静默降级。
     */
    public Map<String, Object> checkUpdate(String currentVersion) throws Exception {
        requireProductCode();
        return request("/product/updateCheck", mapOf("productUniqueCode", productUniqueCode, "currentVersion", currentVersion), false);
    }

    /** 软件内支付后发码（兼容旧签名，不带计费周期） */
    public Map<String, Object> generateForSoftware(String machineCodeValue, String edition, int expiryDays, String clientOrderId) throws Exception {
        return generateForSoftware(machineCodeValue, edition, expiryDays, clientOrderId, null);
    }

    /** 软件内支付后发码；billingPeriod：目标计费周期（同版本多周期产品指定发哪条，缺省取该版本配置首行；QUOTA/周期产品据此固化额度/周期） */
    public Map<String, Object> generateForSoftware(String machineCodeValue, String edition, int expiryDays, String clientOrderId, String billingPeriod) throws Exception {
        requireProductCode();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("productUniqueCode", productUniqueCode);
        body.put("machineCode", machineCodeValue);
        body.put("edition", edition == null ? "" : edition);
        body.put("expiryDays", expiryDays);
        if (billingPeriod != null) body.put("billingPeriod", billingPeriod);
        body.put("clientOrderId", clientOrderId == null ? "" : clientOrderId);
        return request("/license/software/generate", body, true);
    }

    /** 软件内升级/续费（兼容旧签名，不带计费周期） */
    public Map<String, Object> upgradeForSoftware(String licenseCode, String machineCodeValue, String edition, int expiryDays, String clientOrderId) throws Exception {
        return upgradeForSoftware(licenseCode, machineCodeValue, edition, expiryDays, clientOrderId, null);
    }

    /** 软件内升级/续费；billingPeriod：目标计费周期（同版本多周期产品指定升级到哪条，缺省取该版本配置首行） */
    public Map<String, Object> upgradeForSoftware(String licenseCode, String machineCodeValue, String edition, int expiryDays, String clientOrderId, String billingPeriod) throws Exception {
        requireProductCode();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("productUniqueCode", productUniqueCode);
        body.put("licenseCode", licenseCode);
        body.put("machineCode", machineCodeValue);
        body.put("edition", edition);
        body.put("expiryDays", expiryDays);
        if (billingPeriod != null) body.put("billingPeriod", billingPeriod);
        body.put("clientOrderId", clientOrderId == null ? "" : clientOrderId);
        return request("/license/software/upgrade", body, true);
    }

    /** 60s 校验缓存：付费功能点击前调用 */
    public Map<String, Object> verifyCached(String licenseCode, String machineCodeValue, String activationToken) throws Exception {
        long now = System.currentTimeMillis();
        if (verifyCache != null && now - verifyCache.at < cacheTtlMs) {
            return verifyCache.data;
        }
        Map<String, Object> data = verify(licenseCode, machineCodeValue, activationToken);
        verifyCache = new VerifyCacheEntry(now, data);
        return data;
    }

    /**
     * 付费功能未授权时的购买页跳转 URL。
     * 产品标识：构造器 productUniqueCode（开发者中心唯一编码）。
     */
    public String purchaseUrl(String machineCodeValue, String baseUrl) {
        if (productUniqueCode == null || productUniqueCode.isEmpty()) {
            throw new LicenseException("productUniqueCode required", "PRODUCT_ID_REQUIRED");
        }
        String base = (baseUrl == null || baseUrl.isEmpty()) ? "https://www.powersoftware.app" : baseUrl.replaceAll("/+$", "");
        return base + "/product/license/purchase?productUniqueCode=" + URLEncoder.encode(productUniqueCode, StandardCharsets.UTF_8)
                + "&machineCode=" + URLEncoder.encode(machineCodeValue, StandardCharsets.UTF_8);
    }

    public String purchaseUrl(String machineCodeValue) {
        return purchaseUrl(machineCodeValue, null);
    }

    private void requireProductCode() {
        if (productUniqueCode == null || productUniqueCode.isEmpty()) {
            throw new LicenseException("productUniqueCode required", "PRODUCT_ID_REQUIRED");
        }
    }

    public static class LicenseException extends RuntimeException {
        public final String errorCode;

        public LicenseException(String message, String errorCode) {
            super(message);
            this.errorCode = errorCode;
        }
    }

    private static final class VerifyCacheEntry {
        final long at;
        final Map<String, Object> data;

        VerifyCacheEntry(long at, Map<String, Object> data) {
            this.at = at;
            this.data = data;
        }
    }
}
