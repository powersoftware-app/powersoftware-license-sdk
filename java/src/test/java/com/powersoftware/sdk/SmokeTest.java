package com.powersoftware.sdk;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 冒烟测试（无 JUnit 依赖，直接 main 运行）：
 * java -cp target/classes com.powersoftware.sdk.SmokeTest
 */
public class SmokeTest {

    public static void main(String[] args) {
        String mc1 = LicenseClient.machineCode();
        String mc2 = LicenseClient.machineCode();
        check(mc1.equals(mc2), "machineCode stable");
        check(mc1.length() >= 8, "machineCode length");

        Map<String, Object> params = new LinkedHashMap<>();
        params.put("productUniqueCode", "PRO-2026-001");
        params.put("machineCode", "M123");
        params.put("edition", "PRO");
        params.put("expiryDays", 0);
        params.put("clientOrderId", "x");
        params.put("licenseCode", "");
        params.put("timestamp", 1000L);
        check(LicenseClient.sign("secret", params).equals(LicenseClient.sign("secret", params)), "sign deterministic");

        // billingPeriod 必须进入签名串：仅周期不同 → 签名不同（防升级目标周期被篡改）
        Map<String, Object> monthly = new LinkedHashMap<>(params);
        monthly.put("billingPeriod", "MONTHLY");
        Map<String, Object> permanent = new LinkedHashMap<>(params);
        permanent.put("billingPeriod", "PERMANENT");
        check(!LicenseClient.sign("secret", monthly).equals(LicenseClient.sign("secret", permanent)), "sign binds billingPeriod");
        Map<String, Object> mixedCase = new LinkedHashMap<>(params);
        mixedCase.put("billingPeriod", " monthly ");
        check(LicenseClient.sign("secret", mixedCase).equals(LicenseClient.sign("secret", monthly)), "billingPeriod normalized (trim+upper)");

        String url = new LicenseClient("PRO-2026-001", "secret").purchaseUrl("MABC");
        check(url.contains("productUniqueCode=PRO-2026-001") && url.contains("machineCode=MABC") && !url.contains("productId="), "purchaseUrl params");
        String url2 = new LicenseClient("PRO-2026-001", "secret").purchaseUrl("MABC", "https://www.powersoftware.cn");
        check(url2.contains("productUniqueCode=PRO-2026-001") && url2.contains("machineCode=MABC"), "purchaseUrl custom base");
        System.out.println("SmokeTest OK");
    }

    private static void check(boolean cond, String name) {
        if (!cond) {
            throw new AssertionError("FAILED: " + name);
        }
        System.out.println("ok: " + name);
    }
}
