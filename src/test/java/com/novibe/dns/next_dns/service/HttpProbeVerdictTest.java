package com.novibe.dns.next_dns.service;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class HttpProbeVerdictTest {
    @Test void acceptsSuccessAndRedirects() {
        assertTrue(SniProxyHealthChecker.isUsableHttpResponse(200,"OK"));
        assertTrue(SniProxyHealthChecker.isUsableHttpResponse(301,"Moved"));
        assertTrue(SniProxyHealthChecker.isUsableHttpResponse(302,""));
    }
    @Test void rejectsRegionalRefusalInsideSuccessfulResponse() {
        assertFalse(SniProxyHealthChecker.isUsableHttpResponse(200,"unsupported_country_region_territory"));
    }
    @Test void rejectsCloudflareDenialsAndChallenges() {
        assertFalse(SniProxyHealthChecker.isUsableHttpResponse(403,"Request is not allowed"));
        assertFalse(SniProxyHealthChecker.isUsableHttpResponse(403,"<title>Just a moment</title><div>cf-chl-</div>"));
    }
    @Test void rejectsNotFoundRateLimitAndServerErrors() {
        assertFalse(SniProxyHealthChecker.isUsableHttpResponse(404,"Not Found"));
        assertFalse(SniProxyHealthChecker.isUsableHttpResponse(429,"Too Many Requests"));
        assertFalse(SniProxyHealthChecker.isUsableHttpResponse(503,"Bad Gateway"));
        assertFalse(SniProxyHealthChecker.isUsableHttpResponse(-1,""));
    }
}
