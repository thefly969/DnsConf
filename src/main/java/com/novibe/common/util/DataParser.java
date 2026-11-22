package com.novibe.common.util;

import com.novibe.common.base_structures.HostsLine;
import org.jspecify.annotations.Nullable;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public class DataParser {

    private static final Pattern WHITESPACE = Pattern.compile("\\s+");
    private static final Pattern EOL = Pattern.compile("\\r?\\n");

    public static String removeWWW(String domain) {
        if (domain.startsWith("www.")) {
            return domain.substring("www.".length());
        }
        return domain;
    }

    public static boolean isComment(String line) {
        return line.startsWith("#");
    }

    /**
     * Parses standard hosts records with one or more hostnames per IP:
     * "192.0.2.1 example.com api.example.com www.example.com".
     * www aliases are normalized and duplicate domains on the same line keep
     * their first occurrence.
     */
    public static List<HostsLine> parseHostsLines(String line) {
        String sanitizedLine = stripInlineComment(line);
        if (sanitizedLine.isBlank()) {
            return List.of();
        }

        String[] columns = WHITESPACE.split(sanitizedLine);
        if (columns.length == 1) {
            String value = columns[0];
            if (isValidIP(value)) {
                return List.of(HostsLine.ipOnly(value));
            }
            String domain = removeWWW(value);
            return domain.isBlank() ? List.of() : List.of(HostsLine.domainOnly(domain));
        }

        String ip = columns[0];
        if (!isValidIP(ip)) {
            Log.fail("Failed to parse hosts line: " + line);
            return List.of();
        }

        Set<String> seenDomains = new LinkedHashSet<>();
        List<HostsLine> parsed = new ArrayList<>();
        for (int i = 1; i < columns.length; i++) {
            String domain = removeWWW(columns[i].strip());
            if (!domain.isBlank() && seenDomains.add(domain)) {
                parsed.add(new HostsLine(ip, domain));
            }
        }
        return List.copyOf(parsed);
    }

    /**
     * Backward-compatible single-record parser for callers that expect one
     * HostsLine. ListLoader uses parseHostsLines() to retain every hostname.
     */
    public static @Nullable HostsLine parseHostsLine(String line) {
        List<HostsLine> parsed = parseHostsLines(line);
        return parsed.isEmpty() ? null : parsed.getFirst();
    }

    public static Stream<String> splitByEol(String data) {
        return EOL.splitAsStream(data);
    }

    private static String stripInlineComment(String line) {
        int commentIndex = line.indexOf('#');
        if (commentIndex >= 0) {
            return line.substring(0, commentIndex).strip();
        }
        return line;
    }

    private static boolean isValidIP(String ip) {
        try {
            return !InetAddress.ofLiteral(ip).getHostAddress().isEmpty();
        } catch (Exception e) {
            return false;
        }
    }
}
