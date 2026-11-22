package com.novibe.dns.next_dns.service;

import com.novibe.common.base_structures.BypassRoute;
import com.novibe.common.service.ExcludeRedirectCheckService;
import com.novibe.common.util.Log;
import com.novibe.dns.next_dns.http.NextDnsRateLimitedApiProcessor;
import com.novibe.dns.next_dns.http.NextDnsRewriteClient;
import com.novibe.dns.next_dns.http.dto.request.CreateRewriteDto;
import com.novibe.dns.next_dns.http.dto.response.rewrite.RewriteDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class NextDnsRewriteService {

    private final NextDnsRewriteClient nextDnsRewriteClient;
    private final ExcludeRedirectCheckService excludeRedirectCheckService;

    public Map<String, CreateRewriteDto> buildNewRewrites(List<BypassRoute> overrides) {
        Map<String, CreateRewriteDto> rewriteDtos = new LinkedHashMap<>();
        overrides.forEach(route -> {
            String domain = NextDnsRewriteOptimizer.normalizeDomain(route.website());
            rewriteDtos.putIfAbsent(domain, new CreateRewriteDto(domain, route.ip()));
        });
        return rewriteDtos;
    }

    /**
     * Synchronizes only domains present in the supplied hosts sources. Existing
     * custom rules outside those sources are kept, except for configured excludes.
     * All capacity checks happen before the first write request.
     */
    public void syncRewrites(Map<String, CreateRewriteDto> requestedRewrites) {
        List<RewriteDto> existingRewrites = getExistingRewrites();
        NextDnsRewriteOptimizer.Plan plan = NextDnsRewriteOptimizer.plan(
                requestedRewrites,
                existingRewrites,
                excludeRedirectCheckService::shouldExclude
        );

        Log.common("Hosts domains: %s; existing rewrites: %s; deletes: %s; creates: %s; projected total: %s/%s"
                .formatted(
                        plan.sourceDomainCount(),
                        plan.existingCount(),
                        plan.idsToDelete().size(),
                        plan.rewritesToCreate().size(),
                        plan.projectedCount(),
                        NextDnsRewriteOptimizer.MAX_REWRITES
                ));

        if (!plan.fitsNextDnsLimit()) {
            String message = "NextDNS rewrite limit would be exceeded: projected %s rules, maximum %s. No API changes were sent. "
                    .formatted(plan.projectedCount(), NextDnsRewriteOptimizer.MAX_REWRITES)
                    + "Reduce the source list or add EXCLUDE_REDIRECT domains.";
            Log.fail(message);
            throw new IllegalStateException(message);
        }

        if (!plan.idsToDelete().isEmpty()) {
            Log.step("Remove outdated, excluded and redundant rewrites");
            Set<String> ids = new LinkedHashSet<>(plan.idsToDelete());
            NextDnsRateLimitedApiProcessor.callApi(List.copyOf(ids), nextDnsRewriteClient::deleteRewriteById);
        }

        if (!plan.rewritesToCreate().isEmpty()) {
            // Re-read after deletions in case the profile was edited elsewhere
            // between preflight and POST. Never send a POST that could exceed 500.
            int currentCount = getExistingRewrites().size();
            int actualProjectedCount = currentCount + plan.rewritesToCreate().size();
            if (actualProjectedCount > NextDnsRewriteOptimizer.MAX_REWRITES) {
                String message = "NextDNS profile changed during synchronization: adding %s rules to the current %s would exceed the %s-rule limit. No new rewrites were posted."
                        .formatted(plan.rewritesToCreate().size(), currentCount, NextDnsRewriteOptimizer.MAX_REWRITES);
                Log.fail(message);
                throw new IllegalStateException(message);
            }
            Log.step("Create missing and updated rewrites");
            NextDnsRateLimitedApiProcessor.callApi(plan.rewritesToCreate(), nextDnsRewriteClient::saveRewrite);
        }

        Log.common("NextDNS rewrites synchronized successfully. Final expected count: %s/%s"
                .formatted(plan.projectedCount(), NextDnsRewriteOptimizer.MAX_REWRITES));
    }

    public List<RewriteDto> getExistingRewrites() {
        Log.io("Fetching all existing rewrites from NextDNS (up to the API maximum of 500)");
        return nextDnsRewriteClient.fetchRewrites();
    }

    public void removeAll() {
        Log.io("Fetching existing rewrites from NextDNS");
        List<RewriteDto> list = nextDnsRewriteClient.fetchRewrites();
        List<String> ids = list.stream().map(RewriteDto::id).toList();
        Log.io("Removing rewrites from NextDNS");
        NextDnsRateLimitedApiProcessor.callApi(ids, nextDnsRewriteClient::deleteRewriteById);
    }
}
