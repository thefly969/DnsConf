package com.novibe.common.data_sources;

import com.novibe.common.base_structures.HostsLine;
import com.novibe.common.util.DataParser;
import com.novibe.common.util.Log;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.StructuredTaskScope;
import java.util.function.Predicate;
import java.util.stream.Collectors;

@Setter(onMethod_ = @Autowired)
public abstract class ListLoader<T> {

    private HttpClient client;

    protected abstract T toObject(HostsLine hostsLine);

    protected abstract String listType();

    protected abstract Predicate<HostsLine> filterRelatedLines();

    @SuppressWarnings("preview")
    public List<T> fetchWebsites(List<String> urls) {
        try (var scope = StructuredTaskScope.open()) {
            List<StructuredTaskScope.Subtask<String>> requests = new ArrayList<>();
            urls.stream()
                    .map(url -> scope.fork(() -> fetchList(url)))
                    .forEach(requests::add);
            scope.join();

            // Keep distinct (IP, domain) pairs. A hostname may have several
            // proxy candidates; collapsing by domain here loses all backups.
            return requests.stream()
                    .map(StructuredTaskScope.Subtask::get)
                    .flatMap(DataParser::splitByEol)
                    .map(String::strip)
                    .filter(line -> !line.isBlank())
                    .filter(line -> !DataParser.isComment(line))
                    .map(String::toLowerCase)
                    .flatMap(line -> DataParser.parseHostsLines(line).stream())
                    .filter(Objects::nonNull)
                    .filter(filterRelatedLines())
                    .map(this::toObject)
                    // Deduplicate only after conversion: redirect equality includes
                    // both IP and hostname; blocklist equality is a domain string.
                    .distinct()
                    .collect(Collectors.toCollection(ArrayList::new));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Interrupted while downloading hosts sources", e);
        }
    }

    private String fetchList(String url) throws IOException, InterruptedException {
        Log.io("Loading %s list from url: %s".formatted(listType(), url));
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .GET()
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Hosts source returned HTTP " + response.statusCode() + ": " + url);
        }
        return response.body();
    }

}