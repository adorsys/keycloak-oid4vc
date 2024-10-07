package org.keycloak.quarkus.runtime.configuration.mappers;

import io.smallrye.common.net.Inet;
import io.smallrye.config.ConfigSourceInterceptorContext;
import org.keycloak.config.ProxyOptions;
import org.keycloak.quarkus.runtime.cli.PropertyException;
import org.keycloak.quarkus.runtime.configuration.Configuration;

import java.util.Optional;

import static org.keycloak.quarkus.runtime.configuration.mappers.PropertyMapper.fromOption;

final class ProxyPropertyMappers {

    private ProxyPropertyMappers(){}

    public static PropertyMapper<?>[] getProxyPropertyMappers() {
        return new PropertyMapper[] {
                fromOption(ProxyOptions.PROXY_HEADERS)
                        .to("quarkus.http.proxy.proxy-address-forwarding")
                        .transformer((v, c) -> proxyEnabled(null, v, c))
                        .paramLabel("headers")
                        .build(),
                fromOption(ProxyOptions.PROXY_PROTOCOL_ENABLED)
                        .to("quarkus.http.proxy.use-proxy-protocol")
                        .build(),
                fromOption(ProxyOptions.PROXY_FORWARDED_HOST)
                        .to("quarkus.http.proxy.enable-forwarded-host")
                        .mapFrom("proxy-headers")
                        .transformer((v, c) -> proxyEnabled(null, v, c))
                        .build(),
                fromOption(ProxyOptions.PROXY_FORWARDED_HEADER_ENABLED)
                        .to("quarkus.http.proxy.allow-forwarded")
                        .mapFrom("proxy-headers")
                        .transformer((v, c) -> proxyEnabled(ProxyOptions.Headers.forwarded, v, c))
                        .build(),
                fromOption(ProxyOptions.PROXY_X_FORWARDED_HEADER_ENABLED)
                        .to("quarkus.http.proxy.allow-x-forwarded")
                        .mapFrom("proxy-headers")
                        .transformer((v, c) -> proxyEnabled(ProxyOptions.Headers.xforwarded, v, c))
                        .build(),
                fromOption(ProxyOptions.PROXY_TRUSTED_ADDRESSES)
                        .to("quarkus.http.proxy.trusted-proxies")
                        .validator(ProxyPropertyMappers::validateAddress)
                        .addValidateEnabled(() -> !Configuration.isBlank(ProxyOptions.PROXY_HEADERS), "proxy-headers is set")
                        .paramLabel("trusted proxies")
                        .build()
        };
    }
    
    private static void validateAddress(String address) {
        if (Inet.parseCidrAddress(address) != null) {
            return;
        }
        if (Inet.parseInetAddress(address) == null) {
            throw new PropertyException(address + " is not a valid IP address (IPv4 or IPv6) nor valid CIDR notation.");
        }
    }

    private static Optional<String> proxyEnabled(ProxyOptions.Headers testHeader, Optional<String> value, ConfigSourceInterceptorContext context) {
        boolean enabled = false;

        if (value.isPresent()) { // proxy-headers explicitly configured
            if (testHeader != null) {
                enabled = ProxyOptions.Headers.valueOf(value.get()).equals(testHeader);
            } else {
                enabled = true;
            }
        }

        return Optional.of(String.valueOf(enabled));
    }

}
