package com.novibe.dns.next_dns.service;

import com.novibe.dns.next_dns.http.dto.request.CreateRewriteDto;
import com.novibe.dns.next_dns.http.dto.response.rewrite.RewriteDto;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NextDnsRewriteOptimizerTest {

    @Test
    void removesChildRewriteWhenParentHasSameIp() {
        var plan = NextDnsRewriteOptimizer.plan(
                requested(entry("example.com", "1.2.3.4"), entry("api.example.com", "1.2.3.4")),
                List.of(existing("child-id", "api.example.com", "1.2.3.4")),
                ignored -> false
        );
        assertEquals(List.of("child-id"), plan.idsToDelete());
        assertEquals(List.of("example.com"), names(plan.rewritesToCreate()));
        assertEquals(1, plan.projectedCount());
    }

    @Test
    void preservesChildAsExceptionWhenIpDiffers() {
        var plan = NextDnsRewriteOptimizer.plan(
                requested(entry("example.com", "1.2.3.4"), entry("api.example.com", "5.6.7.8")),
                List.of(), ignored -> false
        );
        assertEquals(List.of("example.com", "api.example.com"), names(plan.rewritesToCreate()));
    }

    @Test
    void comparesWithNearestParentAndNotAnyAncestor() {
        var plan = NextDnsRewriteOptimizer.plan(
                requested(entry("example.com", "1.2.3.4"), entry("a.example.com", "5.6.7.8"),
                        entry("b.a.example.com", "1.2.3.4")),
                List.of(), ignored -> false
        );
        assertEquals(List.of("example.com", "a.example.com", "b.a.example.com"), names(plan.rewritesToCreate()));
    }

    @Test
    void existingManualParentCanCoverSourceDomain() {
        var plan = NextDnsRewriteOptimizer.plan(
                requested(entry("api.example.com", "1.2.3.4")),
                List.of(existing("manual-parent", "example.com", "1.2.3.4")),
                ignored -> false
        );
        assertTrue(plan.idsToDelete().isEmpty());
        assertTrue(plan.rewritesToCreate().isEmpty());
        assertEquals(1, plan.projectedCount());
    }

    @Test
    void keepsManualChildNotPresentInSource() {
        var plan = NextDnsRewriteOptimizer.plan(
                requested(entry("example.com", "1.2.3.4")),
                List.of(existing("manual-child", "api.example.com", "5.6.7.8")),
                ignored -> false
        );
        assertTrue(plan.idsToDelete().isEmpty());
        assertEquals(List.of("example.com"), names(plan.rewritesToCreate()));
        assertEquals(2, plan.projectedCount());
    }

    @Test
    void doesNotTreatPartialLabelSuffixAsSubdomain() {
        var plan = NextDnsRewriteOptimizer.plan(
                requested(entry("notexample.com", "1.2.3.4")),
                List.of(existing("parent", "example.com", "1.2.3.4")),
                ignored -> false
        );
        assertEquals(List.of("notexample.com"), names(plan.rewritesToCreate()));
    }

    @Test
    void deletesExistingChildIfItsSourceEntryNowMatchesParent() {
        var plan = NextDnsRewriteOptimizer.plan(
                requested(entry("example.com", "1.2.3.4"), entry("api.example.com", "1.2.3.4")),
                List.of(existing("parent", "example.com", "1.2.3.4"),
                        existing("child", "api.example.com", "5.6.7.8")),
                ignored -> false
        );
        assertEquals(List.of("child"), plan.idsToDelete());
        assertTrue(plan.rewritesToCreate().isEmpty());
        assertEquals(1, plan.projectedCount());
    }

    @Test
    void reportsOverflowBeforeAnyApiMutation() {
        List<RewriteDto> existing = java.util.stream.IntStream.range(0, 500)
                .mapToObj(i -> existing("id-" + i, "manual-" + i + ".example", "10.0.0.1"))
                .toList();
        var plan = NextDnsRewriteOptimizer.plan(requested(entry("new.example", "1.2.3.4")),
                existing, ignored -> false);
        assertEquals(501, plan.projectedCount());
        assertFalse(plan.fitsNextDnsLimit());
    }

    private static Map<String, CreateRewriteDto> requested(CreateRewriteDto... entries) {
        Map<String, CreateRewriteDto> map = new LinkedHashMap<>();
        for (CreateRewriteDto entry : entries) map.put(entry.name(), entry);
        return map;
    }

    private static CreateRewriteDto entry(String domain, String ip) {
        return new CreateRewriteDto(domain, ip);
    }

    private static RewriteDto existing(String id, String domain, String ip) {
        return new RewriteDto(id, domain, ip);
    }

    private static List<String> names(List<CreateRewriteDto> rewrites) {
        return rewrites.stream().map(CreateRewriteDto::name).toList();
    }
}
