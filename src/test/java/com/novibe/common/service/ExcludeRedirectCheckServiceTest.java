package com.novibe.common.service;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExcludeRedirectCheckServiceTest {

    @Test
    void matchesExactDomainsAndTrueSubdomainsOnly() {
        List<String> exclusions = List.of("naukri.com", "naukimg.com");

        assertTrue(ExcludeRedirectCheckService.matchesAny(exclusions, "naukri.com"));
        assertTrue(ExcludeRedirectCheckService.matchesAny(exclusions, "jobs.naukri.com"));
        assertTrue(ExcludeRedirectCheckService.matchesAny(exclusions, "static.naukimg.com"));

        assertFalse(ExcludeRedirectCheckService.matchesAny(exclusions, "notnaukri.com"));
        assertFalse(ExcludeRedirectCheckService.matchesAny(exclusions, "naukri.com.example"));
        assertFalse(ExcludeRedirectCheckService.matchesAny(exclusions, "gemini.google.com"));
    }
}
