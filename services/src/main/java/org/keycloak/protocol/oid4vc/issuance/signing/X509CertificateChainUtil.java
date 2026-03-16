package org.keycloak.protocol.oid4vc.issuance.signing;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;

/**
 * Helper for preparing X.509 certificate chains to be used in JOSE {@code x5c} headers.
 * <p>
 * The logic encapsulates HAIP-6.1.1 requirements so that call sites don't need
 * to reimplement self-signed and trust-anchor filtering.
 */
public final class X509CertificateChainUtil {

    private static final Logger LOGGER = Logger.getLogger(X509CertificateChainUtil.class);

    private X509CertificateChainUtil() {
        // utility class
    }

    /**
     * Normalizes a certificate chain for use in an {@code x5c} header, enforcing HAIP-6.1.1:
     * <ul>
     *   <li>The signing certificate (first in the chain) MUST NOT be self-signed.</li>
     *   <li>The trust anchor (self-signed root CA) MUST NOT be included.</li>
     * </ul>
     * <p>
     * Behaviour:
     * <ul>
     *   <li>Null or empty input returns an empty list.</li>
     *   <li>Null entries are filtered out.</li>
     *   <li>If the first certificate is self-signed, an empty list is returned (x5c must be omitted).</li>
     *   <li>Trailing self-signed certificates are removed (assumed trust anchors).</li>
     *   <li>If all certificates are self-signed, an empty list is returned.</li>
     * </ul>
     *
     * @param certificateChain original chain from the signing key / key store
     * @return filtered chain suitable for x5c, or empty list if x5c should be omitted
     */
    public static List<X509Certificate> normalizeForX5c(List<X509Certificate> certificateChain) {
        if (certificateChain == null || certificateChain.isEmpty()) {
            return List.of();
        }

        List<X509Certificate> filteredChain = certificateChain.stream()
                .filter(Objects::nonNull)
                .collect(Collectors.toCollection(ArrayList::new));

        if (filteredChain.isEmpty()) {
            return List.of();
        }

        // Signing certificate (first in chain) MUST NOT be self-signed.
        X509Certificate signingCert = filteredChain.get(0);
        if (isSelfSigned(signingCert)) {
            LOGGER.debugf("Signing certificate is self-signed; omitting x5c header per HAIP-6.1.1.");
            return List.of();
        }

        // Remove trailing self-signed certificates (trust anchors).
        while (!filteredChain.isEmpty() && isSelfSigned(filteredChain.get(filteredChain.size() - 1))) {
            filteredChain.remove(filteredChain.size() - 1);
        }

        if (filteredChain.isEmpty()) {
            LOGGER.debugf("All certificates in chain were self-signed (trust anchors); omitting x5c header per HAIP-6.1.1.");
            return List.of();
        }

        return filteredChain;
    }

    private static boolean isSelfSigned(X509Certificate cert) {
        return cert != null
                && cert.getSubjectX500Principal() != null
                && cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
    }
}

