package org.keycloak.protocol.oid4vc.issuance.keybinding;

import java.util.HashMap;
import java.util.Map;

import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.broker.provider.TrustMaterialResolver;
import org.keycloak.constants.OID4VCIConstants;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.utils.StringUtil;

import org.jboss.logging.Logger;

/**
 * Shared trusted-key loader for attestation-aware proof validators.
 */
public final class TrustedAttestationKeysLoader {

    private static final Logger logger = Logger.getLogger(TrustedAttestationKeysLoader.class);

    private TrustedAttestationKeysLoader() {
    }

    /**
     * Loads trusted keys for attestation validation from configured trust-material IdPs in client.
     * The trust-material IdP aliases are configured via client attribute
     * {@link OID4VCIConstants#OID4VCI_ATTESTER_TRUST_IDPS_ATTR}.
     *
     * @return a map of key ID to JWK for all resolved trusted keys, generating key IDs for keys without them
     */
    public static Map<String, JWK> loadTrustedKeys(KeycloakSession session) {
        ClientModel client = session.getContext().getClient();
        if (client == null) {
            logger.debugf("Cannot load trust-material IdP aliases because client is null");
            return Map.of();
        }

        String trustIdpsConfig = client.getAttribute(OID4VCIConstants.OID4VCI_ATTESTER_TRUST_IDPS_ATTR);
        if (StringUtil.isBlank(trustIdpsConfig)) {
            logger.debugf("No trust-material IdP aliases configured for client: %s", client.getClientId());
            return Map.of();
        }

        // Load all public keys from configured trust-material identity providers
        // Use an empty TrustMaterialRequest to load keys without filtering by kid, algorithm, or issuer
        TrustMaterialRequest request = TrustMaterialRequest.builder().build();
        Map<String, JWK> trustedKeys = new HashMap<>();

        new TrustMaterialResolver()
                .resolveKeys(session, trustIdpsConfig, request)
                .forEach(jwk -> {
                    String keyId = jwk.getKeyId();
                    // Generate a key ID if the JWK doesn't have one
                    if (StringUtil.isBlank(keyId)) {
                        keyId = KeycloakModelUtils.generateShortId();
                        logger.debugf("Generated key ID '%s' for JWK without explicit key ID from IdP", keyId);
                    }
                    // Only add if we haven't already seen this key ID (keep first occurrence)
                    trustedKeys.putIfAbsent(keyId, jwk);
                });

        logger.infof("Loaded %d trusted keys from IdPs for client: %s", trustedKeys.size(), client.getClientId());
        return trustedKeys;
    }
}
