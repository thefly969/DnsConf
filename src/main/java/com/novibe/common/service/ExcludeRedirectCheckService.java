package com.novibe.common.service;

import com.novibe.common.data_sources.ExcludeRedirectSettingsLoader;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Locale;

@Service
public class ExcludeRedirectCheckService {

    private final List<String> ignoringList;

    public ExcludeRedirectCheckService(ExcludeRedirectSettingsLoader excludeRedirectSettingsLoader) {
        ignoringList = excludeRedirectSettingsLoader.loadIgnoredDomains().stream()
                .map(ExcludeRedirectCheckService::normalizeDomain)
                .filter(domain -> !domain.isEmpty())
                .distinct()
                .toList();
    }

    /**
     * User-defined EXCLUDE_REDIRECT entries exclude the named domain and true
     * subdomains, and keep their established behaviour of deleting matching
     * existing NextDNS rewrites.
     */
    public boolean shouldExclude(String domain) {
        return matchesAny(ignoringList, domain);
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
