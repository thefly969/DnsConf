package com.novibe.dns.next_dns.http;

import com.novibe.dns.next_dns.http.dto.request.CreateRewriteDto;
import com.novibe.dns.next_dns.http.dto.response.rewrite.MultiRewriteResponse;
import com.novibe.dns.next_dns.http.dto.response.rewrite.RewriteDto;
import com.novibe.dns.next_dns.http.dto.response.rewrite.SingleRewriteResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class NextDnsRewriteClient extends AbstractNextDnsHttpClient {

    public List<RewriteDto> fetchRewrites() {
        /*
         * The live /rewrites endpoint rejects the generic limit parameter
         * with HTTP 400 (error code extraneous). Keep this request identical
         * to the form used successfully by the original DnsConf workflow:
         * GET /profiles/{profile}/rewrites.
         *
         * Do not append query parameters unless NextDNS explicitly
         * documents and accepts them for this endpoint.
         */
        MultiRewriteResponse response = get(path(), MultiRewriteResponse.class);
        if (response == null) {
            throw new IllegalStateException("NextDNS returned an empty response while fetching rewrites");
        }
        if (response.getErrors() != null && !response.getErrors().isEmpty()) {
            throw new IllegalStateException("NextDNS API error while fetching rewrites: " + response.getErrors());
        }
        if (response.getData() == null) {
            throw new IllegalStateException("NextDNS response did not contain the rewrites list");
        }
        return response.getData();
    }

    public SingleRewriteResponse saveRewrite(CreateRewriteDto rewriteDto) {
        return post(path(), rewriteDto, SingleRewriteResponse.class);
    }

    public @Nullable SingleRewriteResponse deleteRewriteById(String id) {
        return delete(path() + "/" + id, SingleRewriteResponse.class);
    }

    @Override
    protected String path() {
        return "/rewrites";
    }
}
