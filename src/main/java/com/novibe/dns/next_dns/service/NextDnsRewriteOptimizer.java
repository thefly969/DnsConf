package com.novibe.dns.next_dns.service;

import com.novibe.dns.next_dns.http.dto.request.CreateRewriteDto;
import com.novibe.dns.next_dns.http.dto.response.rewrite.RewriteDto;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
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
        Objects.requireNonNull(requestedRewrites, "requestedRewrites");
        Objects.requireNonNull(existingRewrites, "existingRewrites");
        Objects.requireNonNull(isExcluded, "isExcluded");

        Map<String, CreateRewriteDto> desiredByDomain = new LinkedHashMap<>();
        for (CreateRewriteDto request : requestedRewrites.values()) {
            String domain = normalizeDomain(request.name());
            if (!domain.isBlank() && !isExcluded.test(domain)) {
                // First source wins, matching DnsConf's source-priority behaviour.
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
            if (isExcluded.test(domain)) {
                idsToDelete.add(existing.id());
                continue;
            }
            existingByDomain.putIfAbsent(domain, existing);
            effectiveRules.putIfAbsent(domain, existing.content());
        }

        Map<String, CreateRewriteDto> rewritesToCreate = new LinkedHashMap<>();

        // Parent domains must be processed before their children. The effective
        // map includes existing manual rules and source rules already planned.
        for (CreateRewriteDto desired : desiredInParentFirstOrder) {
            String domain = desired.name();
            String targetIp = desired.content();
            RewriteDto exactExisting = existingByDomain.get(domain);
            String inheritedIp = findNearestAncestorIp(effectiveRules, domain);

            if (Objects.equals(inheritedIp, targetIp)) {
                // The parent already supplies exactly the requested answer.
                // Remove only an exact rule whose domain is explicitly present
                // in the source list; unrelated manual child rules are untouched.
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
                continue;
            }

            if (exactExisting != null && idsToDelete.add(exactExisting.id())) {
                // NextDNS has no rewrite PATCH operation: update = delete + POST.
                effectiveRules.remove(domain);
            }

            rewritesToCreate.put(domain, new CreateRewriteDto(domain, targetIp));
            effectiveRules.put(domain, targetIp);
        }

        int projectedCount = existingRewrites.size() - idsToDelete.size() + rewritesToCreate.size();
        return new Plan(
                List.copyOf(idsToDelete),
                List.copyOf(rewritesToCreate.values()),
                existingRewrites.size(),
                desiredByDomain.size(),
                projectedCount
        );
    }

    /** Normalizes names for DNS suffix comparisons without changing IP contents. */
    public static String normalizeDomain(String value) {
        if (value == null) {
            return "";
        }
        String domain = value.strip().toLowerCase(java.util.Locale.ROOT);
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
            int projectedCount
    ) {
        public boolean fitsNextDnsLimit() {
            return projectedCount <= MAX_REWRITES;
        }
    }
}
