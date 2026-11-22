package com.novibe.common.service;

import com.novibe.common.data_sources.ExcludeRedirectSettingsLoader;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Locale;

@Service
public class ExcludeRedirectCheckService {

    private final List<String> ignoringList;
    private final List<String> sourceIgnoringList;

    public ExcludeRedirectCheckService(ExcludeRedirectSettingsLoader excludeRedirectSettingsLoader) {
        ignoringList = normalize(excludeRedirectSettingsLoader.loadIgnoredDomains());
        sourceIgnoringList = normalize(excludeRedirectSettingsLoader.loadSourceExcludedDomains());
    }

    /**
     * Explicit EXCLUDE_REDIRECT settings keep their existing behaviour:
     * excluded domains are not added and matching existing rewrites are deleted.
     */
    public boolean shouldExclude(String domain) {
        return matchesAny(ignoringList, domain);
    }

    /**
     * Source-only exclusions filter incoming hosts records but do not delete
     * existing manual rewrites in the NextDNS profile.
     */
    public boolean shouldExcludeFromSource(String domain) {
        return matchesAny(ignoringList, domain) || matchesAny(sourceIgnoringList, domain);
    }

    static boolean matchesAny(List<String> domains, String candidate) {
        if (candidate == null || candidate.isBlank()) {
            return false;
        }
        String normalizedCandidate = normalizeDomain(candidate);
        for (String ignored : domains) {
            String normalizedIgnored = normalizeDomain(ignored);
            if (!normalizedIgnored.isEmpty()
                    && (normalizedCandidate.equals(normalizedIgnored)
                    || normalizedCandidate.endsWith("." + normalizedIgnored))) {
                return true;
            }
        }
        return false;
    }

    private static List<String> normalize(List<String> domains) {
        return domains.stream()
                .map(ExcludeRedirectCheckService::normalizeDomain)
                .filter(domain -> !domain.isEmpty())
                .distinct()
                .toList();
    }

    private static String normalizeDomain(String domain) {
        String normalized = domain.strip().toLowerCase(Locale.ROOT);
        while (normalized.startsWith(".")) {
            normalized = normalized.substring(1);
        }
        while (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }
}
