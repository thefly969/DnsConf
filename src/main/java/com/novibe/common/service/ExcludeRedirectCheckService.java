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
                .map(domain -> domain.toLowerCase(Locale.ROOT))
                .toList();
    }

    public boolean shouldExclude(String domain) {
        String candidate = domain.toLowerCase(Locale.ROOT);
        for (String ignored : ignoringList) {
            // A domain is excluded only if it is the ignored domain or a true
            // subdomain. Avoid accidental matches such as notexample.com.
            if (candidate.equals(ignored) || candidate.endsWith("." + ignored)) {
                return true;
            }
        }
        return false;
    }
}
