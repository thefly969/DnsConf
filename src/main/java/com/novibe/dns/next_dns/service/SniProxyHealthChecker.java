package com.novibe.dns.next_dns.service;

import com.novibe.common.base_structures.BypassRoute;
import com.novibe.common.util.Log;
import org.springframework.stereotype.Service;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;

@Service
public class SniProxyHealthChecker implements TlsSniProbe {

    private static final int MAX_PARALLEL_PROBES = 32;
    private static final int CONNECT_TIMEOUT_MILLIS = 2_500;
    private static final int TLS_TIMEOUT_MILLIS = 3_000;
    private static final int HTTP_TIMEOUT_MILLIS = 3_000;
    private static final int MAX_STATUS_LINE_LENGTH = 1_024;
    private static final int MAX_RESPONSE_BODY_CHARS = 8_192;
    private static final int MAX_RESPONSE_HEADER_CHARS = 32_768;

    @Override
    public Set<BypassRoute> findHealthy(List<BypassRoute> candidates) {
        List<BypassRoute> uniqueCandidates = List.copyOf(new LinkedHashSet<>(candidates));
        if (uniqueCandidates.isEmpty()) {
            return Set.of();
        }

        Semaphore permits = new Semaphore(MAX_PARALLEL_PROBES);
        Set<BypassRoute> healthy = new LinkedHashSet<>();
        List<Future<Boolean>> checks = new ArrayList<>(uniqueCandidates.size());

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            for (BypassRoute candidate : uniqueCandidates) {
                checks.add(executor.submit(() -> {
                    permits.acquire();
                    try {
                        return hasValidHttpsRoute(candidate);
                    } finally {
                        permits.release();
                    }
                }));
            }

            for (int i = 0; i < checks.size(); i++) {
                try {
                    if (checks.get(i).get()) {
                        healthy.add(uniqueCandidates.get(i));
                    }
                } catch (ExecutionException e) {
                    Log.fail("SNI/TLS probe failed unexpectedly for " + uniqueCandidates.get(i).website());
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while checking SMART redirect routes", e);
        }

        Log.common("HTTPS/SNI validation: %s/%s IP-domain pairs returned an HTTP response below 500; %s failed."
                .formatted(healthy.size(), uniqueCandidates.size(), uniqueCandidates.size() - healthy.size()));
        return Collections.unmodifiableSet(healthy);
    }

    private boolean hasValidHttpsRoute(BypassRoute route) {
        String domain = route.website() == null
                ? ""
                : route.website().strip().toLowerCase(Locale.ROOT);
        String ip = route.ip() == null ? "" : route.ip().strip();

        if (domain.isBlank() || ip.isBlank()) {
            return false;
        }

        try {
            InetAddress address = InetAddress.ofLiteral(ip);
            if (address.isAnyLocalAddress()
                    || address.isLoopbackAddress()
                    || address.isLinkLocalAddress()
                    || address.isSiteLocalAddress()
                    || address.isMulticastAddress()) {
                return false;
            }

            try (Socket tcp = new Socket()) {
                tcp.connect(new InetSocketAddress(address, 443), CONNECT_TIMEOUT_MILLIS);
                tcp.setSoTimeout(TLS_TIMEOUT_MILLIS);

                SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                try (SSLSocket tls = (SSLSocket) factory.createSocket(tcp, domain, 443, true)) {
                    SSLParameters parameters = tls.getSSLParameters();
                    parameters.setServerNames(List.of(new SNIHostName(domain)));
                    // A successful handshake is not sufficient if the endpoint
                    // presents a certificate invalid for the requested hostname.
                    parameters.setEndpointIdentificationAlgorithm("HTTPS");
                    parameters.setApplicationProtocols(new String[]{"http/1.1"});
                    tls.setSSLParameters(parameters);
                    tls.setSoTimeout(TLS_TIMEOUT_MILLIS);
                    tls.startHandshake();
                    tls.setSoTimeout(HTTP_TIMEOUT_MILLIS);
                    return receivesHttpResponse(tls, domain);
                }
            }
        } catch (IOException | IllegalArgumentException | SecurityException e) {
            return false;
        }
    }

    private boolean receivesHttpResponse(SSLSocket tls, String domain) throws IOException {
        String request;
        if ("ws.chatgpt.com".equals(domain)) {
            // Without a logged-in session the endpoint may return an authorization
            // error, but the WebSocket upgrade request must reach the HTTP server.
            request = "GET / HTTP/1.1\r\n"
                    + "Host: ws.chatgpt.com\r\n"
                    + "Origin: https://chatgpt.com\r\n"
                    + "Upgrade: websocket\r\n"
                    + "Connection: Upgrade\r\n"
                    + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    + "Sec-WebSocket-Version: 13\r\n"
                    + "User-Agent: Mozilla/5.0 DnsConfRouteProbe\r\n\r\n";
        } else {
            request = "GET / HTTP/1.1\r\n"
                    + "Host: " + domain + "\r\n"
                    + "User-Agent: DnsHostsGenerator/1.5.3 DnsConfRouteProbe\r\n"
                    + "Accept: */*\r\n"
                    + "Connection: close\r\n\r\n";
        }

        tls.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
        tls.getOutputStream().flush();

        BufferedReader reader = new BufferedReader(
                new InputStreamReader(tls.getInputStream(), StandardCharsets.UTF_8),
                8 * 1024
        );
        String statusLine = reader.readLine();
        if (statusLine == null
                || (!statusLine.startsWith("HTTP/1.0 ") && !statusLine.startsWith("HTTP/1.1 "))) {
            return false;
        }

        String[] parts = statusLine.split("\\s+", 3);
        if (parts.length < 2) {
            return false;
        }

        int statusCode;
        try {
            statusCode = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            return false;
        }

        int headerChars = 0;
        String header;
        while ((header = reader.readLine()) != null && !header.isEmpty()) {
            headerChars += header.length();
            if (headerChars > MAX_RESPONSE_HEADER_CHARS) {
                return false;
            }
        }

        // A valid WebSocket upgrade has no HTTP response body to inspect.
        if (statusCode == 101) {
            return true;
        }

        StringBuilder body = new StringBuilder();
        char[] buffer = new char[1_024];
        while (body.length() < MAX_RESPONSE_BODY_CHARS) {
            try {
                int count = reader.read(
                        buffer,
                        0,
                        Math.min(buffer.length, MAX_RESPONSE_BODY_CHARS - body.length())
                );
                if (count < 0) {
                    break;
                }
                body.append(buffer, 0, count);
            } catch (SocketTimeoutException timeout) {
                // Some endpoints keep connections alive despite Connection: close.
                // A complete status + headers and no regional marker are still useful.
                break;
            }
        }

        return isUsableHttpResponse(statusCode, body.toString());
    }

    /**
     * Match DnsHostsGenerator 1.5.3's HTTP verdict policy:
     * explicit region refusal is disqualifying; Cloudflare's anonymous
     * "Request is not allowed" and bot challenges are not, by themselves,
     * proof that the route cannot serve a logged-in application session.
     */
    static boolean isUsableHttpResponse(int statusCode, String body) {
        if (statusCode < 100 || statusCode >= 500) {
            return false;
        }
        return body == null
                || !body.toLowerCase(Locale.ROOT).contains("unsupported_country_region_territory");
    }

}
