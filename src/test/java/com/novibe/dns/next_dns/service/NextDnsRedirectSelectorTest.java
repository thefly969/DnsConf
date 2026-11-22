package com.novibe.dns.next_dns.service;

import com.novibe.common.base_structures.BypassRoute;
import com.novibe.dns.next_dns.http.dto.response.rewrite.RewriteDto;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NextDnsRedirectSelectorTest {

    @Test
    void selectsSecondIpWhenFirstCandidateFailsTls() {
        BypassRoute first = new BypassRoute("192.0.2.1", "example.com");
        BypassRoute second = new BypassRoute("192.0.2.2", "example.com");
        NextDnsRedirectSelector selector = new NextDnsRedirectSelector(candidates -> Set.of(second));

        var result = selector.select(
                List.of(first, second),
                Set.of("example.com"),
                List.of(),
                ignored -> false
        );

        assertEquals("192.0.2.2", result.rewrites().get("example.com").content());
        assertEquals(1, result.healthyDomainCount());
        assertEquals(0, result.retainedExistingCount());
    }

    @Test
    void prefersHealthyParentIpForChildToAllowSafeRewriteCompression() {
        BypassRoute parent = new BypassRoute("192.0.2.10", "example.com");
        BypassRoute childFirst = new BypassRoute("192.0.2.20", "api.example.com");
        BypassRoute childShared = new BypassRoute("192.0.2.10", "api.example.com");
        NextDnsRedirectSelector selector = new NextDnsRedirectSelector(candidates -> Set.copyOf(candidates));

        var result = selector.select(
                List.of(parent, childFirst, childShared),
                Set.of("example.com", "api.example.com"),
                List.of(),
                ignored -> false
        );

        assertEquals("192.0.2.10", result.rewrites().get("example.com").content());
        assertEquals("192.0.2.10", result.rewrites().get("api.example.com").content());
    }

    @Test
    void preservesCurrentMappingWhenNoCandidatePassesTlsProbe() {
        BypassRoute candidate = new BypassRoute("192.0.2.30", "example.com");
        RewriteDto existing = new RewriteDto("existing-id", "example.com", "192.0.2.40");
        NextDnsRedirectSelector selector = new NextDnsRedirectSelector(ignored -> Set.of());

        var result = selector.select(
                List.of(candidate),
                Set.of("example.com"),
                List.of(existing),
                ignored -> false
        );

        assertEquals("192.0.2.40", result.rewrites().get("example.com").content());
        assertEquals(0, result.healthyDomainCount());
        assertEquals(1, result.retainedExistingCount());
    }

    @Test
    void neverAddsCandidatesOutsideThePrimarySmartAllowlist() {
        BypassRoute allowed = new BypassRoute("192.0.2.50", "allowed.example");
        BypassRoute unrelated = new BypassRoute("192.0.2.60", "unrelated.example");
        NextDnsRedirectSelector selector = new NextDnsRedirectSelector(candidates -> Set.copyOf(candidates));

        var result = selector.select(
                List.of(allowed, unrelated),
                Set.of("allowed.example"),
                List.of(),
                ignored -> false
        );

        assertTrue(result.rewrites().containsKey("allowed.example"));
        assertFalse(result.rewrites().containsKey("unrelated.example"));
        assertEquals(1, result.eligibleDomainCount());
    }

    @Test
    void preservesManualParentAndReusesItsIpWhenTheChildCandidatePasses() {
        BypassRoute child = new BypassRoute("192.0.2.70", "api.example.com");
        RewriteDto manualParent = new RewriteDto("manual-parent", "example.com", "192.0.2.70");
        NextDnsRedirectSelector selector = new NextDnsRedirectSelector(candidates -> Set.copyOf(candidates));

        var result = selector.select(
                List.of(child),
                Set.of("api.example.com"),
                List.of(manualParent),
                ignored -> false
        );

        assertEquals("192.0.2.70", result.rewrites().get("api.example.com").content());
    }
}
