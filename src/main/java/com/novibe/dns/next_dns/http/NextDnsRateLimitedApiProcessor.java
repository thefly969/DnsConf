package com.novibe.dns.next_dns.http;

import com.novibe.common.exception.DnsHttpError;
import com.novibe.common.util.Log;
import com.novibe.dns.next_dns.http.dto.response.NextDnsResponse;
import lombok.experimental.UtilityClass;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

@UtilityClass
public class NextDnsRateLimitedApiProcessor {

    // Stay below the documented NextDNS write limit of 60 requests per minute.
    private static final long MIN_REQUEST_INTERVAL_NANOS = TimeUnit.MILLISECONDS.toNanos(1_100);
    private static long nextRequestAtNanos;

    public <D, R extends NextDnsResponse<?>> void callApi(List<D> requestList, Function<D, R> request) {
        int successfulRequests = 0;
        for (int i = 0; i < requestList.size(); i++) {
            D requestDto = requestList.get(i);
            awaitNextRequestSlot();
            try {
                R response = request.apply(requestDto);
                if (response != null && response.getErrors() != null && !response.getErrors().isEmpty()) {
                    throw new IllegalStateException("NextDNS API returned errors: " + response.getErrors());
                }
                successfulRequests++;
                Log.progress("Current success progress: " + (i + 1) + "/" + requestList.size());
            } catch (DnsHttpError e) {
                if (e.getCode() == 524 || e.getCode() == 429) {
                    Log.common("\nNextDNS rate limit or timeout reached after %s successful requests".formatted(successfulRequests));
                    i--;
                    runRateLimiterResetWaitTimer();
                    successfulRequests = 0;
                    Log.io("Continue...");
                } else {
                    throw e;
                }
            }
        }
        Log.common("\nCompleted");
    }

    private static synchronized void awaitNextRequestSlot() {
        long now = System.nanoTime();
        long waitNanos = nextRequestAtNanos - now;
        if (waitNanos > 0) {
            try {
                TimeUnit.NANOSECONDS.sleep(waitNanos);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("Interrupted while waiting for the NextDNS API rate limit", e);
            }
        }
        nextRequestAtNanos = System.nanoTime() + MIN_REQUEST_INTERVAL_NANOS;
    }

    private void runRateLimiterResetWaitTimer() {
        final int waitSeconds = 60;
        for (int timer = waitSeconds; timer > 0; timer--) {
            try {
                Thread.sleep(Duration.of(1, ChronoUnit.SECONDS));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("Interrupted while waiting for the NextDNS rate limit reset", e);
            }
            Log.progress("Waiting for reset: " + timer + " seconds");
        }
    }
}
