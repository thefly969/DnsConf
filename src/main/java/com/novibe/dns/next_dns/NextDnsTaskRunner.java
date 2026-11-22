package com.novibe.dns.next_dns;

import com.novibe.common.DnsTaskRunner;
import com.novibe.common.base_structures.BypassRoute;
import com.novibe.common.service.ExcludeRedirectCheckService;
import com.novibe.common.util.EnvParser;
import com.novibe.common.util.Log;
import com.novibe.dns.next_dns.http.dto.request.CreateRewriteDto;
import com.novibe.dns.next_dns.service.NextDnsDenyService;
import com.novibe.dns.next_dns.service.NextDnsRedirectSelector;
import com.novibe.dns.next_dns.service.NextDnsRewriteOptimizer;
import com.novibe.dns.next_dns.service.NextDnsRewriteService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.novibe.common.config.EnvironmentVariables.BLOCK;
import static com.novibe.common.config.EnvironmentVariables.REDIRECT;
import static com.novibe.common.config.EnvironmentVariables.REDIRECT_CANDIDATES;
import static com.novibe.common.config.EnvironmentVariables.REDIRECT_FALLBACK;

@Service
@RequiredArgsConstructor
public class NextDnsTaskRunner extends DnsTaskRunner {

    private static final int MINIMUM_SMART_DOMAINS = 100;
    private static final int MINIMUM_HEALTHY_DOMAINS = 150;
    private static final double MINIMUM_HEALTHY_RATIO = 0.40;
    // Exact mobile app profiles from DnsHostsGenerator 1.5.3 (22.11.2026).
    // These are based on observed ChatGPT/Gemini Android traffic, not broad parent wildcards.
    private static final List<String> ADDITIONAL_SERVICE_DOMAINS = List.of(
            "chatgpt.com",
            "ws.chatgpt.com",
            "ab.chatgpt.com",
            "codex-cloud-backend.chatgpt.com",
            "android.chat.openai.com",
            "aw.api.openai.com",
            "cdn.platform.openai.com",
            "auth.openai.com",
            "auth0.openai.com",
            "cdn.auth0.com",
            "chat.openai.com",
            "ios.chat.openai.com",
            "api.openai.com",
            "platform.openai.com",
            "cdn.oaistatic.com",
            "files.oaiusercontent.com",
            "openai.com",
            "gemini.google.com",
            "aistudio.google.com",
            "makersuite.google.com",
            "bard.google.com",
            "generativelanguage.googleapis.com",
            "aisandbox-pa.googleapis.com",
            "assistant-s3-pa.googleapis.com",
            "proactivebackend-pa.googleapis.com",
            "robinfrontend-pa.googleapis.com",
            "alkalicore-pa.clients6.google.com",
            "alkalimakersuite-pa.clients6.google.com",
            "webchannel-alkalimakersuite-pa.clients6.google.com",
            "people-pa.clients6.google.com",
            "signaler-pa.clients6.google.com",
            "waa-pa.clients6.google.com",
            "deepmind.google",
            "jules.google.com",
            "notebooklm.google.com",
            "labs.google",
            // Additional web-app dependencies from official network guidance.
            "www.googleapis.com",
            "ssl.gstatic.com",
            "fonts.googleapis.com",
            "apis.google.com",
            "jnn-pa.googleapis.com",
            "lh3.googleusercontent.com",
            "lh5.googleusercontent.com",
            "ogs.google.com",
            "cdn.openaimerge.com",
            "cdn.workos.com",
            "forwarder.workos.com",
            "frontend-apps-multi-region.workos.com",
            "images.workoscdn.com",
            "js.intercomcdn.com",
            "js.stripe.com",
            "setup.workos.com",
            "workos.imgix.net"
    );

    // Candidate observed in DnsHostsGenerator 1.5.3 with api.bezshansov.ru DoT.
    // Release notes report HTTP 200/302 for these exact domains; it is still
    // re-probed from this runner before it can become a NextDNS rewrite.
    private static final List<BypassRoute> DNS_HOSTS_GENERATOR_CANDIDATES = List.of(
            new BypassRoute("77.90.47.224", "gemini.google.com"),
            new BypassRoute("77.90.47.224", "aistudio.google.com"),
            new BypassRoute("77.90.47.224", "generativelanguage.googleapis.com"),
            new BypassRoute("77.90.47.224", "chatgpt.com"),
            new BypassRoute("77.90.47.224", "auth.openai.com")
    );

    private final NextDnsRewriteService nextDnsRewriteService;
    private final NextDnsDenyService nextDnsDenyService;
    private final NextDnsRedirectSelector nextDnsRedirectSelector;
    private final ExcludeRedirectCheckService excludeRedirectCheckService;

    @Override
    public void greetingMessage() {
        Log.global("Setting up Profile " + dnsProfile.number() + " (NextDNS)");
        Log.common("""
                Script behaviour: provided BLOCK/REDIRECT sources are synchronized with the profile.
                - SMART proxy addresses are preferred; alternative provider addresses are tested next.
                - direct Crutch mappings are used only as a last resort and only after HTTPS/SNI validation.
                - every candidate is checked for TCP 443, TLS hostname validation and an actual HTTP response.
                - the ChatGPT WebSocket host is additionally checked with an HTTP Upgrade request.
                - exact ChatGPT (17) and Gemini (19) Android profiles come from DnsHostsGenerator 1.5.3.
                - HTTP verdict policy rejects explicit regional refusal but tolerates anonymous Cloudflare blocks and bot challenges.
                - a recently tested api.bezshansov.ru candidate is re-probed before use; its published IP is not trusted blindly.
                - alternative proxy IPs for these hosts are tested individually; no broad Google parent domains are added.
                - failed probes preserve an existing profile mapping as last-known-good.
                - a minimum share of domains must pass live validation before the profile can be changed.
                - DONOR_DNS substitution is disabled because it would replace a tested proxy IP with an ordinary DNS answer.
                - a NextDNS rewrite covers the domain and its subdomains.
                - redundant child rewrites with the same IP as their nearest parent are removed.
                - stale source-managed rules are removed using the GitHub manifest.
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

        List<String> primarySources = EnvParser.parse(REDIRECT);
        List<String> fallbackSources = EnvParser.parse(REDIRECT_FALLBACK);
        List<String> candidateSources = EnvParser.parse(REDIRECT_CANDIDATES);

        if (!primarySources.isEmpty()) {
            Log.step("Load preferred SMART proxy mappings");
            List<BypassRoute> primaryRoutes = overrideListsLoader.fetchWebsites(primarySources);

            Log.step("Load SMART direct-mapping fallback domains");
            List<BypassRoute> fallbackRoutes = fallbackSources.isEmpty()
                    ? List.of()
                    : overrideListsLoader.fetchWebsites(fallbackSources);

            Set<String> allowlist = new LinkedHashSet<>();
            primaryRoutes.forEach(route -> allowlist.add(NextDnsRewriteOptimizer.normalizeDomain(route.website())));
            fallbackRoutes.forEach(route -> allowlist.add(NextDnsRewriteOptimizer.normalizeDomain(route.website())));
            allowlist.addAll(ADDITIONAL_SERVICE_DOMAINS);
            allowlist.remove("");

            if (allowlist.size() < MINIMUM_SMART_DOMAINS) {
                throw new IllegalStateException("SMART sources returned only %s unique domains; minimum expected is %s. "
                        .formatted(allowlist.size(), MINIMUM_SMART_DOMAINS)
                        + "Refusing to change the NextDNS profile because the upstream source may be incomplete.");
            }

            Log.step("Load alternative proxy IP candidates");
            List<BypassRoute> alternativeRoutes = candidateSources.isEmpty()
                    ? List.of()
                    : overrideListsLoader.fetchWebsites(candidateSources);

            // Priority: SMART's preferred proxy mappings, all-provider proxy
            // alternatives restricted to SMART domains, then direct Crutch.
            List<BypassRoute> orderedCandidates = new ArrayList<>(primaryRoutes);
            alternativeRoutes.stream()
                    .filter(route -> allowlist.contains(NextDnsRewriteOptimizer.normalizeDomain(route.website())))
                    .forEach(orderedCandidates::add);
            orderedCandidates.addAll(fallbackRoutes);
            orderedCandidates.addAll(DNS_HOSTS_GENERATOR_CANDIDATES);

            // Reuse only the public proxy IPs already present in the upstream SMART pools.
            // Each additional service hostname is tested independently before it can be rewritten.
            LinkedHashSet<String> proxyIps = new LinkedHashSet<>();
            primaryRoutes.stream().map(BypassRoute::ip)
                    .filter(ip -> ip != null && !ip.isBlank()).forEach(proxyIps::add);
            alternativeRoutes.stream().map(BypassRoute::ip)
                    .filter(ip -> ip != null && !ip.isBlank()).forEach(proxyIps::add);

            int additionalCandidateCount = 0;
            for (String domain : ADDITIONAL_SERVICE_DOMAINS) {
                for (String ip : proxyIps) {
                    orderedCandidates.add(new BypassRoute(ip, domain));
                    additionalCandidateCount++;
                }
            }

            long allowedAlternatives = alternativeRoutes.stream()
                    .filter(route -> allowlist.contains(NextDnsRewriteOptimizer.normalizeDomain(route.website())))
                    .count();
            Log.common("SMART allowlist: %s domains; preferred mappings: %s; alternative mappings in allowlist: %s; direct fallback mappings: %s."
                    .formatted(allowlist.size(), primaryRoutes.size(), allowedAlternatives, fallbackRoutes.size()));
            Log.common("Additional service hosts: %s; candidate proxy IPs: %s; extra IP-host checks: %s."
                    .formatted(ADDITIONAL_SERVICE_DOMAINS.size(), proxyIps.size(), additionalCandidateCount));
            Log.common("DnsHostsGenerator 1.5.3 extra candidates: %s (all re-probed)."
                    .formatted(DNS_HOSTS_GENERATOR_CANDIDATES.size()));

            List<com.novibe.dns.next_dns.http.dto.response.rewrite.RewriteDto> existingRewrites =
                    nextDnsRewriteService.getExistingRewrites();

            Log.step("Probe candidate routes using HTTPS/SNI and HTTP");
            NextDnsRedirectSelector.Selection selection = nextDnsRedirectSelector.select(
                    orderedCandidates,
                    allowlist,
                    existingRewrites,
                    excludeRedirectCheckService::shouldExclude
            );

            for (String domain : ADDITIONAL_SERVICE_DOMAINS) {
                CreateRewriteDto selected = selection.rewrites().get(domain);
                if (selected != null) {
                    Log.common("Service route selected: %s -> %s".formatted(domain, selected.content()));
                } else {
                    Log.common("Service route not selected: %s (no candidate passed validation or the domain is excluded)."
                            .formatted(domain));
                }
            }

            int minimumHealthy = Math.max(
                    MINIMUM_HEALTHY_DOMAINS,
                    (int) Math.ceil(selection.eligibleDomainCount() * MINIMUM_HEALTHY_RATIO)
            );
            if (selection.healthyDomainCount() < minimumHealthy) {
                throw new IllegalStateException("Only %s/%s SMART domains passed live HTTPS/SNI/HTTP validation; at least %s are required. "
                        .formatted(selection.healthyDomainCount(), selection.eligibleDomainCount(), minimumHealthy)
                        + "No NextDNS rewrites were changed. The current profile remains intact.");
            }

            if (selection.rewrites().isEmpty()) {
                throw new IllegalStateException("No usable SMART redirect routes were selected. NextDNS profile was not changed.");
            }

            Log.step("Prepare and optimize validated redirects");
            Map<String, CreateRewriteDto> requests = selection.rewrites();
            nextDnsRewriteService.syncRewrites(requests);
        } else {
            Log.fail("No primary SMART rewrite sources provided");
        }

        if (blockSources.isEmpty() && primarySources.isEmpty()) {
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