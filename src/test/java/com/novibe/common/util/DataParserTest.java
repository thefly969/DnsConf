package com.novibe.common.util;

import com.novibe.common.base_structures.HostsLine;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DataParserTest {

    @Test
    void parsesSeveralDomainsFromOneHostsLine() {
        List<HostsLine> rows = DataParser.parseHostsLines(
                "192.0.2.10 example.com api.example.com www.example.com # tested"
        );

        assertEquals(List.of("example.com", "api.example.com"),
                rows.stream().map(HostsLine::domain).toList());
        assertEquals(List.of("192.0.2.10", "192.0.2.10"),
                rows.stream().map(HostsLine::ip).toList());
    }

    @Test
    void keepsDomainOnlyRecordsForBlockLists() {
        List<HostsLine> rows = DataParser.parseHostsLines("tracker.example");

        assertEquals(1, rows.size());
        assertEquals("tracker.example", rows.getFirst().domain());
        assertTrue(rows.getFirst().hasDomainOnly());
    }

    @Test
    void ignoresInlineCommentsAndBlankLines() {
        assertTrue(DataParser.parseHostsLines("   # comment").isEmpty());
        assertTrue(DataParser.parseHostsLines("192.0.2.10 example.com # comment").stream()
                .allMatch(row -> "example.com".equals(row.domain())));
    }
}
