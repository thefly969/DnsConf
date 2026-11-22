package com.novibe.common.data_sources;

import com.novibe.common.base_structures.BypassRoute;
import com.novibe.common.base_structures.HostsLine;
import org.springframework.stereotype.Service;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.function.Predicate;

@Service
public class HostsOverrideListsLoader extends ListLoader<BypassRoute> {

    @Override
    protected String listType() {
        return "Override";
    }

    @Override
    protected Predicate<HostsLine> filterRelatedLines() {
        return line -> line.hasIpAndDomain() && isUsableRedirectIp(line.ip());
    }

    @Override
    protected BypassRoute toObject(HostsLine line) {
        return new BypassRoute(line.ip(), line.domain());
    }

    static boolean isUsableRedirectIp(String value) {
        try {
            InetAddress address = InetAddress.ofLiteral(value);
            if (address.isAnyLocalAddress()
                    || address.isLoopbackAddress()
                    || address.isLinkLocalAddress()
                    || address.isSiteLocalAddress()
                    || address.isMulticastAddress()) {
                return false;
            }

            byte[] bytes = address.getAddress();
            if (address instanceof Inet4Address) {
                int first = bytes[0] & 0xff;
                int second = bytes[1] & 0xff;
                // Carrier-grade NAT is not a public proxy destination.
                if (first == 100 && second >= 64 && second <= 127) {
                    return false;
                }
                // Limited broadcast.
                if (first == 255 && second == 255
                        && (bytes[2] & 0xff) == 255 && (bytes[3] & 0xff) == 255) {
                    return false;
                }
            } else if (address instanceof Inet6Address) {
                // IPv6 unique-local space (fc00::/7) is not globally routable.
                if ((bytes[0] & 0xfe) == 0xfc) {
                    return false;
                }
            }
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
