package com.novibe.common.data_sources;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExcludeRedirectSettingsLoaderTest {

    @Test
    void loadsCuratedSourceExclusionsFromResource() {
        List<String> domains = new ExcludeRedirectSettingsLoader().loadSourceExcludedDomains();

        assertEquals(84, domains.size());
        assertTrue(domains.contains("naukri.com"));
        assertTrue(domains.contains("naukimg.com"));
        assertFalse(domains.contains("chatgpt.com"));
        assertFalse(domains.contains("gemini.google.com"));
        assertFalse(domains.contains("xiaomi.eu"));
    }
}
