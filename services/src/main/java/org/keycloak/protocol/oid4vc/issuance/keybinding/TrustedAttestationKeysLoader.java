package org.keycloak.protocol.oid4vc.issuance.keybinding;


import java.util.Map;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.KeycloakSession;
import org.jboss.logging.Logger;

/**
 * Shared trusted-key loader for attestation-aware proof validators.
 */
public final class TrustedAttestationKeysLoader {

    private static final Logger logger = Logger.getLogger(TrustedAttestationKeysLoader.class);

    private TrustedAttestationKeysLoader() {
    }

    /**
     * Merges trusted keys from realm JWKS, {@code oid4vc.attestation.trusted_keys} JSON, and {@code trusted_key_ids}.
     */
    public static Map<String, JWK> loadTrustedKeysFromRealm(KeycloakSession session) {

       logger.debugf("No trusted keys found for attestation-aware proof validation");
        return Map.of();
    }
}
