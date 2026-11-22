package com.novibe.common.data_sources;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HostsOverrideListsLoaderTest {

    @Test
    void acceptsPublicProxyIps() {
        assertTrue(HostsOverrideListsLoader.isUsableRedirectIp("45.13.237.213"));
        assertTrue(HostsOverrideListsLoader.isUsableRedirectIp("2a02:e00:ffec:4b8::1"));
    }

    @Test
    void rejectsLoopbackPrivateLinkLocalAndMulticastIps() {
        assertFalse(HostsOverrideListsLoader.isUsableRedirectIp("127.0.0.1"));
        assertFalse(HostsOverrideListsLoader.isUsableRedirectIp("192.168.1.10"));
        assertFalse(HostsOverrideListsLoader.isUsableRedirectIp("169.254.1.10"));
        assertFalse(HostsOverrideListsLoader.isUsableRedirectIp("100.64.0.1"));
        assertFalse(HostsOverrideListsLoader.isUsableRedirectIp("::1"));
        assertFalse(HostsOverrideListsLoader.isUsableRedirectIp("ff02::1"));
        assertFalse(HostsOverrideListsLoader.isUsableRedirectIp("fd00::1"));
    }
}
