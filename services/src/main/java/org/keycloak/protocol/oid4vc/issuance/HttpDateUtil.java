package org.keycloak.protocol.oid4vc.issuance;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import org.keycloak.common.util.Time;

/**
 * Utility for generating HTTP Date header values compliant with RFC 7231 (RFC 1123 format).
 * <p>
 * Uses {@link Time#currentTime()} so tests and time-skew handling remain consistent with
 * the rest of Keycloak.
 */
public final class HttpDateUtil {

    private HttpDateUtil() {
        // utility class
    }

    /**
     * Returns the current time formatted as an HTTP Date header value (RFC 1123).
     */
    public static String nowAsHttpDate() {
        long nowSeconds = Time.currentTime();
        ZonedDateTime now = Instant.ofEpochSecond(nowSeconds).atZone(ZoneOffset.UTC);
        return DateTimeFormatter.RFC_1123_DATE_TIME.format(now);
    }
}

