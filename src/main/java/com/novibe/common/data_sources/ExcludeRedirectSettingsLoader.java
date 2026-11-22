package com.novibe.common.data_sources;

import com.novibe.common.config.EnvironmentVariables;
import com.novibe.common.util.DataParser;
import com.novibe.common.util.EnvParser;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

@Service
public class ExcludeRedirectSettingsLoader {

    public List<String> loadIgnoredDomains() {
        return Optional.ofNullable(EnvParser.parse(EnvironmentVariables.EXCLUDE_REDIRECT))
                .stream()
                .flatMap(List::stream)
                .map(String::trim)
                .map(String::toLowerCase)
                .map(DataParser::removeWWW)
                .distinct()
                .toList();
    }

    /**
     * Loads repository-maintained exclusions for incoming redirect sources.
     * Unlike EXCLUDE_REDIRECT, these exclusions do not delete existing manual rules.
     */
    public List<String> loadSourceExcludedDomains() {
        try (var input = getClass().getResourceAsStream("/nextdns-redirect-source-exclusions.txt")) {
            if (input == null) {
                throw new IllegalStateException("Missing resource: /nextdns-redirect-source-exclusions.txt");
            }
            return new String(input.readAllBytes(), StandardCharsets.UTF_8)
                    .lines()
                    .map(String::trim)
                    .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                    .map(String::toLowerCase)
                    .map(DataParser::removeWWW)
                    .distinct()
                    .toList();
        } catch (IOException e) {
            throw new IllegalStateException("Unable to read NextDNS source exclusions", e);
        }
    }
}
