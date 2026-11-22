package com.novibe.dns.next_dns.service;

import com.novibe.common.base_structures.BypassRoute;

import java.util.List;
import java.util.Set;

@FunctionalInterface
public interface TlsSniProbe {

    /**
     * Returns IP/domain pairs for which a TLS handshake with the domain as SNI
     * succeeded. Implementations must preserve route equality by IP + domain.
     */
    Set<BypassRoute> findHealthy(List<BypassRoute> candidates);
}