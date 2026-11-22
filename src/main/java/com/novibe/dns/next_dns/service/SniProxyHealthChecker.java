package com.novibe.dns.next_dns.service;

import com.novibe.common.base_structures.BypassRoute;
import com.novibe.common.util.Log;
import org.springframework.stereotype.Service;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
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
                        return hasValidTlsRoute(candidate);
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

        Log.common("TLS/SNI validation: %s/%s IP-domain pairs passed; %s failed."
                .formatted(healthy.size(), uniqueCandidates.size(), uniqueCandidates.size() - healthy.size()));
        return Collections.unmodifiableSet(healthy);
    }

    private boolean hasValidTlsRoute(BypassRoute route) {
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
                    tls.setSSLParameters(parameters);
                    tls.startHandshake();
                    return true;
                }
            }
        } catch (IOException | IllegalArgumentException | SecurityException e) {
            return false;
        }
    }
}