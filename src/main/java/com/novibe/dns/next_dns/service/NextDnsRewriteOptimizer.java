package com.novibe.dns.next_dns.service;

import com.novibe.dns.next_dns.http.dto.request.CreateRewriteDto;
import com.novibe.dns.next_dns.http.dto.response.rewrite.RewriteDto;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;

/**
 * Builds a safe NextDNS rewrite sync plan while taking into account that a rewrite
 * applies to the domain and all of its subdomains.
 */
public final class NextDnsRewriteOptimizer {

    public static final int MAX_REWRITES = 500;

    private NextDnsRewriteOptimizer() {
    }

    public static Plan plan(
            Map<String, CreateRewriteDto> requestedRewrites,
            List<RewriteDto> existingRewrites,
            Predicate<String> isExcluded
    ) {
        return plan(requestedRewrites, existingRewrites, isExcluded, Set.of());
    }

    /**
     * The managed-domain manifest identifies exact NextDNS rules created by an
     * earlier synchronization. Stale rules from previous source versions can be
     * removed without touching unrelated user-created rules.
     */
    public static Plan plan(
            Map<String, CreateRewriteDto> requestedRewrites,
            List<RewriteDto> existingRewrites,
            Predicate<String> isExcluded,
            Set<String> previouslyManagedDomains
    ) {
        Objects.requireNonNull(requestedRewrites, "requestedRewrites");
        Objects.requireNonNull(existingRewrites, "existingRewrites");
        Objects.requireNonNull(isExcluded, "isExcluded");
        Objects.requireNonNull(previouslyManagedDomains, "previouslyManagedDomains");

        Set<String> previouslyManaged = new HashSet<>();
        previouslyManagedDomains.stream()
                .map(NextDnsRewriteOptimizer::normalizeDomain)
                .filter(domain -> !domain.isBlank())
                .forEach(previouslyManaged::add);

        Map<String, CreateRewriteDto> desiredByDomain = new LinkedHashMap<>();
        for (CreateRewriteDto request : requestedRewrites.values()) {
            String domain = normalizeDomain(request.name());
            if (!domain.isBlank() && !isExcluded.test(domain)) {
                // First source wins, matching the source-priority behaviour.
                desiredByDomain.putIfAbsent(domain, new CreateRewriteDto(domain, request.content()));
            }
        }

        List<CreateRewriteDto> desiredInParentFirstOrder = new ArrayList<>(desiredByDomain.values());
        desiredInParentFirstOrder.sort(Comparator
                .comparingInt((CreateRewriteDto dto) -> labelCount(dto.name()))
                .thenComparing(CreateRewriteDto::name));

        Map<String, RewriteDto> existingByDomain = new LinkedHashMap<>();
        Map<String, String> effectiveRules = new HashMap<>();
        Set<String> idsToDelete = new LinkedHashSet<>();

        for (RewriteDto existing : existingRewrites) {
            String domain = normalizeDomain(existing.name());
            if (domain.isBlank()) {
                continue;
            }

            boolean explicitlyExcluded = isExcluded.test(domain);
            boolean staleManagedRule = previouslyManaged.contains(domain) && !desiredByDomain.containsKey(domain);
            if (explicitlyExcluded || staleManagedRule) {
                idsToDelete.add(existing.id());
                continue;
            }

            existingByDomain.putIfAbsent(domain, existing);
            effectiveRules.putIfAbsent(domain, existing.content());
        }

        Map<String, CreateRewriteDto> rewritesToCreate = new LinkedHashMap<>();
        Set<String> managedRuleDomainsAfterSync = new LinkedHashSet<>();

        // Parent domains must be processed before their children. The effective
        // map includes existing manual rules and source rules already planned.
        for (CreateRewriteDto desired : desiredInParentFirstOrder) {
            String domain = desired.name();
            String targetIp = desired.content();
            RewriteDto exactExisting = existingByDomain.get(domain);
            String inheritedIp = findNearestAncestorIp(effectiveRules, domain);

            if (Objects.equals(inheritedIp, targetIp)) {
                // The parent already supplies exactly the requested answer.
                // Remove only an exact rule for a domain explicitly in the source.
                if (exactExisting != null && idsToDelete.add(exactExisting.id())) {
                    effectiveRules.remove(domain);
                }
                continue;
            }

            if (exactExisting != null
                    && !idsToDelete.contains(exactExisting.id())
                    && Objects.equals(exactExisting.content(), targetIp)) {
                // The exact rule already provides the requested answer.
                effectiveRules.put(domain, targetIp);
                managedRuleDomainsAfterSync.add(domain);
                continue;
            }

            if (exactExisting != null && idsToDelete.add(exactExisting.id())) {
                // NextDNS has no rewrite PATCH operation: update = delete + POST.
                effectiveRules.remove(domain);
            }

            rewritesToCreate.put(domain, new CreateRewriteDto(domain, targetIp));
            effectiveRules.put(domain, targetIp);
            managedRuleDomainsAfterSync.add(domain);
        }

        int projectedCount = existingRewrites.size() - idsToDelete.size() + rewritesToCreate.size();
        return new Plan(
                List.copyOf(idsToDelete),
                List.copyOf(rewritesToCreate.values()),
                existingRewrites.size(),
                desiredByDomain.size(),
                projectedCount,
                Set.copyOf(managedRuleDomainsAfterSync)
        );
    }

    /** Normalizes names for DNS suffix comparisons without changing IP contents. */
    public static String normalizeDomain(String value) {
        if (value == null) {
            return "";
        }
        String domain = value.strip().toLowerCase(Locale.ROOT);
        while (domain.startsWith(".")) {
            domain = domain.substring(1);
        }
        while (domain.endsWith(".")) {
            domain = domain.substring(0, domain.length() - 1);
        }
        return domain;
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

    public record Plan(
            List<String> idsToDelete,
            List<CreateRewriteDto> rewritesToCreate,
            int existingCount,
            int sourceDomainCount,
            int projectedCount,
            Set<String> managedRuleDomainsAfterSync
    ) {
        public boolean fitsNextDnsLimit() {
            return projectedCount <= MAX_REWRITES;
        }
    }
}
