package com.novibe.dns.next_dns;

import com.novibe.common.DnsTaskRunner;
import com.novibe.common.base_structures.BypassRoute;
import com.novibe.common.util.EnvParser;
import com.novibe.common.util.Log;
import com.novibe.dns.next_dns.http.dto.request.CreateRewriteDto;
import com.novibe.dns.next_dns.service.NextDnsDenyService;
import com.novibe.dns.next_dns.service.NextDnsRewriteService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

import static com.novibe.common.config.EnvironmentVariables.BLOCK;
import static com.novibe.common.config.EnvironmentVariables.REDIRECT;

@Service
@RequiredArgsConstructor
public class NextDnsTaskRunner extends DnsTaskRunner {

    private static final int MINIMUM_SMART_SOURCE_DOMAINS = 100;

    private final NextDnsRewriteService nextDnsRewriteService;
    private final NextDnsDenyService nextDnsDenyService;

    @Override
    public void greetingMessage() {
        Log.global("Setting up Profile " + dnsProfile.number() + " (NextDNS)");
        Log.common("""
                Script behaviour: provided BLOCK/REDIRECT sources are synchronized with the profile.
                - hosts lines may contain multiple hostnames for one IP; every hostname is parsed.
                - duplicate domains keep the first source mapping deterministically.
                - the SMART source contains IP/domain pairs individually checked by upstream TLS/SNI probes.
                - direct "Crutch" mappings are retained as published by the source.
                - NextDNS preserves the source IPs; DONOR_DNS substitution is intentionally disabled here.
                - a NextDNS rewrite covers the domain and its subdomains.
                - redundant child rewrites with the same IP as their nearest parent are removed.
                - child rewrites with a different IP are retained as explicit exceptions.
                - stale source-managed rules are removed using a manifest committed by GitHub Actions.
                - the projected rewrite count is checked against the 500-rule limit before any rewrite changes.
                - API writes are paced below the documented 60 requests per minute limit.
                """);
    }

    @Override
    protected void process() {
        List<String> blockSources = EnvParser.parse(BLOCK);
        if (!blockSources.isEmpty()) {
            Log.step("Obtain block lists from %s sources".formatted(blockSources.size()));
            List<String> blocks = blockListsLoader.fetchWebsites(blockSources);
            Log.step("Prepare denylist");
            List<String> filteredBlocklist = nextDnsDenyService.omitExistingDenys(blocks);
            Log.common("Prepared %s domains to block".formatted(filteredBlocklist.size()));
            Log.step("Save denylist");
            nextDnsDenyService.saveDenyList(filteredBlocklist);
        } else {
            Log.fail("No block sources provided");
        }

        List<String> rewriteSources = EnvParser.parse(REDIRECT);
        if (!rewriteSources.isEmpty()) {
            Log.step("Obtain rewrite lists from %s sources".formatted(rewriteSources.size()));
            List<BypassRoute> overrides = overrideListsLoader.fetchWebsites(rewriteSources);
            Log.common("Loaded %s distinct redirect domains from SMART hosts sources; source IPs are kept unchanged."
                    .formatted(overrides.size()));

            if (overrides.size() < MINIMUM_SMART_SOURCE_DOMAINS) {
                throw new IllegalStateException("SMART hosts source returned only %s redirect domains; minimum expected is %s. "
                        .formatted(overrides.size(), MINIMUM_SMART_SOURCE_DOMAINS)
                        + "Refusing to change the NextDNS profile because the upstream source may be incomplete.");
            }

            Log.step("Prepare and optimize rewrites");
            Map<String, CreateRewriteDto> requests = nextDnsRewriteService.buildNewRewrites(overrides);
            nextDnsRewriteService.syncRewrites(requests);
        } else {
            Log.fail("No rewrite sources provided");
        }

        if (blockSources.isEmpty() && rewriteSources.isEmpty()) {
            Log.step("Remove settings");
            nextDnsDenyService.removeAll();
            nextDnsRewriteService.removeAll();
        }
    }

    @Override
    protected void finishMessage() {
        Log.global("Profile " + dnsProfile.number() + " (NextDNS) set up successfully");
    }
}
