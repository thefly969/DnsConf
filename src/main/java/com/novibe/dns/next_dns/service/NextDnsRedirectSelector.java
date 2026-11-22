package com.novibe.dns.next_dns.service;

import com.novibe.common.base_structures.BypassRoute;
import com.novibe.common.util.Log;
import com.novibe.dns.next_dns.http.dto.request.CreateRewriteDto;
import com.novibe.dns.next_dns.http.dto.response.rewrite.RewriteDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;

@Service
@RequiredArgsConstructor
public class NextDnsRedirectSelector {

    private final TlsSniProbe tlsSniProbe;

    /**
     * Selects the first working proxy for every SMART domain. Candidate IPs are
     * ordered by source priority and restricted to the SMART domain allowlist.
     */
    public Selection select(
            List<BypassRoute> orderedCandidates,
            Set<String> allowedDomains,
            List<RewriteDto> existingRewrites,
            Predicate<String> isExcluded
    ) {
        Objects.requireNonNull(orderedCandidates, "orderedCandidates");
        Objects.requireNonNull(allowedDomains, "allowedDomains");
        Objects.requireNonNull(existingRewrites, "existingRewrites");
        Objects.requireNonNull(isExcluded, "isExcluded");

        Set<String> normalizedAllowlist = allowedDomains.stream()
                .map(NextDnsRewriteOptimizer::normalizeDomain)
                .filter(domain -> !domain.isBlank())
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));

        List<String> domains = normalizedAllowlist.stream()
                .filter(domain -> !isExcluded.test(domain))
                .sorted(Comparator.comparingInt(NextDnsRedirectSelector::labelCount)
                        .thenComparing(Comparator.naturalOrder()))
                .toList();
        Set<String> eligibleDomains = Set.copyOf(domains);

        Map<String, List<BypassRoute>> candidatesByDomain = new LinkedHashMap<>();
        Set<BypassRoute> distinctCandidates = new LinkedHashSet<>();
        for (BypassRoute candidate : orderedCandidates) {
            String domain = NextDnsRewriteOptimizer.normalizeDomain(candidate.website());
            String ip = candidate.ip() == null ? "" : candidate.ip().strip();
            if (domain.isBlank() || ip.isBlank()
                    || !eligibleDomains.contains(domain)
                    || isExcluded.test(domain)) {
                continue;
            }

            BypassRoute normalized = new BypassRoute(ip, domain);
            if (distinctCandidates.add(normalized)) {
                candidatesByDomain.computeIfAbsent(domain, ignored -> new ArrayList<>()).add(normalized);
            }
        }

        List<BypassRoute> candidatesToProbe = List.copyOf(distinctCandidates);
        Set<BypassRoute> healthyCandidates = tlsSniProbe.findHealthy(candidatesToProbe);

        Map<String, RewriteDto> existingByDomain = new LinkedHashMap<>();
        Map<String, String> effectiveRules = new HashMap<>();
        for (RewriteDto existing : existingRewrites) {
            String domain = NextDnsRewriteOptimizer.normalizeDomain(existing.name());
            if (domain.isBlank()) {
                continue;
            }
            existingByDomain.putIfAbsent(domain, existing);

            // Existing rules outside the SMART allowlist are user-managed. They
            // may cover a SMART child if that child's own candidate validates.
            if (!eligibleDomains.contains(domain) && !isExcluded.test(domain)
                    && existing.content() != null && !existing.content().isBlank()) {
                effectiveRules.putIfAbsent(domain, existing.content());
            }
        }

        Map<String, CreateRewriteDto> selected = new LinkedHashMap<>();
        int healthyDomainCount = 0;
        int retainedExistingCount = 0;
        int skippedDomainCount = 0;

        for (String domain : domains) {
            List<BypassRoute> healthyForDomain = candidatesByDomain.getOrDefault(domain, List.of())
                    .stream()
                    .filter(healthyCandidates::contains)
                    .toList();

            String inheritedIp = findNearestAncestorIp(effectiveRules, domain);
            String selectedIp = healthyForDomain.stream()
                    .filter(route -> Objects.equals(route.ip(), inheritedIp))
                    .map(BypassRoute::ip)
                    .findFirst()
                    .orElseGet(() -> healthyForDomain.isEmpty() ? null : healthyForDomain.getFirst().ip());

            if (selectedIp != null) {
                healthyDomainCount++;
            } else {
                RewriteDto existing = existingByDomain.get(domain);
                if (existing != null && existing.content() != null && !existing.content().isBlank()) {
                    // If the GitHub runner cannot validate any current candidate,
                    // preserve the profile's existing mapping as last-known-good.
                    // The task runner requires a minimum live-success ratio before
                    // any profile changes are allowed.
                    selectedIp = existing.content();
                    retainedExistingCount++;
                } else {
                    skippedDomainCount++;
                    continue;
                }
            }

            selected.put(domain, new CreateRewriteDto(domain, selectedIp));
            effectiveRules.put(domain, selectedIp);
        }

        Log.common("SMART route selection: %s domains; %s validated; %s retained from current profile; %s skipped; %s candidate pairs tested."
                .formatted(domains.size(), healthyDomainCount, retainedExistingCount,
                        skippedDomainCount, candidatesToProbe.size()));

        return new Selection(
                selected,
                domains.size(),
                healthyDomainCount,
                retainedExistingCount,
                skippedDomainCount,
                candidatesToProbe.size(),
                healthyCandidates.size()
        );
    }

    private static String findNearestAncestorIp(Map<String, String> rules, String domain) {
        int dot = domain.indexOf('.');
        while (dot >= 0) {
            String parent = domain.substring(dot + 1);
            String parentIp = rules.get(parent);
            if (parentIp != null) {
                return parentIp;
            }
            dot = domain.indexOf('.', dot + 1);
        }
        return null;
    }

    private static int labelCount(String domain) {
        int labels = 1;
        for (int i = 0; i < domain.length(); i++) {
            if (domain.charAt(i) == '.') {
                labels++;
            }
        }
        return labels;
    }

    public record Selection(
            Map<String, CreateRewriteDto> rewrites,
            int eligibleDomainCount,
            int healthyDomainCount,
            int retainedExistingCount,
            int skippedDomainCount,
            int testedCandidateCount,
            int healthyCandidateCount
    ) {
    }
}