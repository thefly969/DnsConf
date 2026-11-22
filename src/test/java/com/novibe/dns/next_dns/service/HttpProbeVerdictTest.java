package com.novibe.dns.next_dns.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HttpProbeVerdictTest {

    @Test
    void rejectsExplicitRegionalRefusalEvenWhenStatusIsSuccessful() {
        assertFalse(SniProxyHealthChecker.isUsableHttpResponse(
                200,
                "{\"error\":\"unsupported_country_region_territory\"}"
        ));
    }

    @Test
    void acceptsCloudflareAnonymousRequestDenial() {
        assertTrue(SniProxyHealthChecker.isUsableHttpResponse(
                403,
                "{\"cf_details\":\"Request is not allowed\"}"
        ));
    }

    @Test
    void acceptsBotChallengeBecauseItDoesNotProveApplicationSessionWillFail() {
        assertTrue(SniProxyHealthChecker.isUsableHttpResponse(
                403,
                "<html><title>Just a moment</title><div>cf-chl-</div></html>"
        ));
    }

    @Test
    void acceptsGoogleNotFoundForApiOrServiceRoot() {
        assertTrue(SniProxyHealthChecker.isUsableHttpResponse(404, "Not Found"));
    }

    @Test
    void rejectsServerErrorsAndMissingHttpResponse() {
        assertFalse(SniProxyHealthChecker.isUsableHttpResponse(503, "Bad Gateway"));
        assertFalse(SniProxyHealthChecker.isUsableHttpResponse(-1, ""));
    }
}
