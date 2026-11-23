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
import java.util.*;
import java.util.concurrent.*;

@Service
public class SniProxyHealthChecker implements TlsSniProbe {
    private static final int MAX_PARALLEL_PROBES=32, CONNECT_TIMEOUT_MILLIS=2500, TLS_TIMEOUT_MILLIS=3000,
            HTTP_TIMEOUT_MILLIS=3000, MAX_RESPONSE_BODY_CHARS=8192, MAX_RESPONSE_HEADER_CHARS=32768;

    @Override public Set<BypassRoute> findHealthy(List<BypassRoute> candidates) {
        List<BypassRoute> unique=List.copyOf(new LinkedHashSet<>(candidates));
        if(unique.isEmpty()) return Set.of();
        Semaphore permits=new Semaphore(MAX_PARALLEL_PROBES);
        Set<BypassRoute> healthy=new LinkedHashSet<>();
        List<Future<Boolean>> checks=new ArrayList<>();
        try(ExecutorService executor=Executors.newVirtualThreadPerTaskExecutor()) {
            for(BypassRoute candidate:unique) checks.add(executor.submit(()->{
                permits.acquire(); try{return hasValidHttpsRoute(candidate);} finally{permits.release();}
            }));
            for(int i=0;i<checks.size();i++) try {
                if(checks.get(i).get()) healthy.add(unique.get(i));
            } catch(ExecutionException e){Log.fail("SNI/TLS probe failed unexpectedly for "+unique.get(i).website());}
        } catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException("Interrupted while checking SMART redirect routes",e);}
        Log.common("HTTPS/SNI validation: %s/%s IP-domain pairs passed HTTP checks; %s failed."
                .formatted(healthy.size(),unique.size(),unique.size()-healthy.size()));
        return Collections.unmodifiableSet(healthy);
    }

    private boolean hasValidHttpsRoute(BypassRoute route) {
        String domain=route.website()==null?"":route.website().strip().toLowerCase(Locale.ROOT);
        String ip=route.ip()==null?"":route.ip().strip();
        if(domain.isBlank()||ip.isBlank()) return false;
        try {
            InetAddress address=InetAddress.ofLiteral(ip);
            if(address.isAnyLocalAddress()||address.isLoopbackAddress()||address.isLinkLocalAddress()
                    ||address.isSiteLocalAddress()||address.isMulticastAddress()) return false;
            try(Socket tcp=new Socket()) {
                tcp.connect(new InetSocketAddress(address,443),CONNECT_TIMEOUT_MILLIS); tcp.setSoTimeout(TLS_TIMEOUT_MILLIS);
                SSLSocketFactory factory=(SSLSocketFactory)SSLSocketFactory.getDefault();
                try(SSLSocket tls=(SSLSocket)factory.createSocket(tcp,domain,443,true)) {
                    SSLParameters p=tls.getSSLParameters(); p.setServerNames(List.of(new SNIHostName(domain)));
                    p.setEndpointIdentificationAlgorithm("HTTPS"); p.setApplicationProtocols(new String[]{"http/1.1"});
                    tls.setSSLParameters(p); tls.setSoTimeout(TLS_TIMEOUT_MILLIS); tls.startHandshake();
                    tls.setSoTimeout(HTTP_TIMEOUT_MILLIS); return receivesHttpResponse(tls,domain);
                }
            }
        } catch(IOException|IllegalArgumentException|SecurityException e){return false;}
    }

    private boolean receivesHttpResponse(SSLSocket tls,String domain) throws IOException {
        String request="GET / HTTP/1.1\r\nHost: "+domain+"\r\nUser-Agent: DnsHostsGenerator/1.5.3 DnsConfRouteProbe\r\nAccept: */*\r\nConnection: close\r\n\r\n";
        if("ws.chatgpt.com".equals(domain)) request="GET / HTTP/1.1\r\nHost: ws.chatgpt.com\r\nOrigin: https://chatgpt.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        tls.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII)); tls.getOutputStream().flush();
        BufferedReader reader=new BufferedReader(new InputStreamReader(tls.getInputStream(),StandardCharsets.UTF_8),8192);
        String status=reader.readLine();
        if(status==null||(!status.startsWith("HTTP/1.0 ")&&!status.startsWith("HTTP/1.1 "))) return false;
        String[] parts=status.split("\\s+",3); if(parts.length<2)return false;
        int code; try{code=Integer.parseInt(parts[1]);}catch(NumberFormatException e){return false;}
        int headers=0; String line;
        while((line=reader.readLine())!=null&&!line.isEmpty()){headers+=line.length();if(headers>MAX_RESPONSE_HEADER_CHARS)return false;}
        if(code==101)return "ws.chatgpt.com".equals(domain);
        StringBuilder body=new StringBuilder(); char[] buf=new char[1024];
        while(body.length()<MAX_RESPONSE_BODY_CHARS) try {
            int n=reader.read(buf,0,Math.min(buf.length,MAX_RESPONSE_BODY_CHARS-body.length()));
            if(n<0)break; body.append(buf,0,n);
        } catch(SocketTimeoutException timeout){break;}
        return isUsableHttpResponse(code,body.toString());
    }

    // 2xx/3xx and 401 (normal unauthenticated API response) pass. 403/404/429
    // are not evidence of a usable route; regional and Cloudflare denials fail.
    static boolean isUsableHttpResponse(int code,String body) {
        if(code<200||code>=400)return false;
        String b=body==null?"":body.toLowerCase(Locale.ROOT);
        return !b.contains("unsupported_country_region_territory")
                && !b.contains("request is not allowed") && !b.contains("cf-chl-")
                && !b.contains("<title>just a moment");
    }
}
