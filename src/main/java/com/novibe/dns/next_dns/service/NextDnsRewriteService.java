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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class NextDnsRewriteService {

    private static final Path MANAGED_STATE_PATH = Path.of("state", "managed-nextdns-rewrites.txt");

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
     * Synchronizes supplied hosts mappings. Exact rules created by previous runs
     * are tracked in a repository manifest so obsolete source entries can be
     * removed without deleting unrelated user-created rewrites.
     */
    public void syncRewrites(Map<String, CreateRewriteDto> requestedRewrites) {
        List<RewriteDto> existingRewrites = getExistingRewrites();
        Set<String> previouslyManagedDomains = loadManagedDomains();
        NextDnsRewriteOptimizer.Plan plan = NextDnsRewriteOptimizer.plan(
                requestedRewrites,
                existingRewrites,
                excludeRedirectCheckService::shouldExclude,
                previouslyManagedDomains
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
                    + "Remove less important source domains or user-created rules before retrying.";
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

        // Verify the result through a fresh API read before advancing the
        // source-managed manifest. A partial API update must not be recorded
        // as a completed migration.
        List<RewriteDto> finalRewrites = getExistingRewrites();
        int finalCount = finalRewrites.size();
        if (finalCount > NextDnsRewriteOptimizer.MAX_REWRITES) {
            throw new IllegalStateException("NextDNS profile returned %s rewrites after synchronization; maximum is %s."
                    .formatted(finalCount, NextDnsRewriteOptimizer.MAX_REWRITES));
        }

        Set<String> finalDomainNames = finalRewrites.stream()
                .map(rewrite -> NextDnsRewriteOptimizer.normalizeDomain(rewrite.name()))
                .collect(Collectors.toSet());
        Set<String> missingManagedRules = plan.managedRuleDomainsAfterSync().stream()
                .filter(domain -> !finalDomainNames.contains(domain))
                .collect(Collectors.toSet());
        if (!missingManagedRules.isEmpty()) {
            throw new IllegalStateException("NextDNS did not return %s expected source-managed rewrites. The state manifest was not updated."
                    .formatted(missingManagedRules.size()));
        }

        persistManagedDomains(plan.managedRuleDomainsAfterSync());
        Log.common("NextDNS rewrites synchronized successfully. Final actual count: %s/%s; source-managed explicit rules: %s"
                .formatted(finalCount, NextDnsRewriteOptimizer.MAX_REWRITES, plan.managedRuleDomainsAfterSync().size()));
    }

    private Set<String> loadManagedDomains() {
        if (!Files.exists(MANAGED_STATE_PATH)) {
            Log.common("No previous source-managed rewrite manifest found; preserving existing profile rules unless they match the new source.");
            return Set.of();
        }
        try {
            return Files.readAllLines(MANAGED_STATE_PATH, StandardCharsets.UTF_8).stream()
                    .map(String::strip)
                    .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                    .map(NextDnsRewriteOptimizer::normalizeDomain)
                    .filter(domain -> !domain.isEmpty())
                    .collect(Collectors.toCollection(LinkedHashSet::new));
        } catch (IOException e) {
            throw new IllegalStateException("Unable to read managed NextDNS rewrite manifest: " + MANAGED_STATE_PATH, e);
        }
    }

    private void persistManagedDomains(Set<String> domains) {
        try {
            Files.createDirectories(MANAGED_STATE_PATH.getParent());
            List<String> lines = domains.stream().sorted().toList();
            Files.write(MANAGED_STATE_PATH, lines, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to write managed NextDNS rewrite manifest: " + MANAGED_STATE_PATH, e);
        }
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
