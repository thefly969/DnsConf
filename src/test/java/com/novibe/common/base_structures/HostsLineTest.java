package com.novibe.common.base_structures;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class HostsLineTest {

    @Test
    void keepsDifferentProxyIpsForTheSameDomainAsDistinctCandidates() {
        HostsLine first = new HostsLine("1.2.3.4", "example.com");
        HostsLine second = new HostsLine("5.6.7.8", "example.com");

        assertNotEquals(first, second);
        assertEquals(first, new HostsLine("1.2.3.4", "example.com"));
    }
}
