package org.keycloak.protocol.oid4vc.issuance.keybinding;

import com.fasterxml.jackson.core.type.TypeReference;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Provider for managing trusted keys for key attestation verification.
 */
import org.keycloak.provider.Provider;

public class KeyAttestationTrustStore implements Provider {

    private final KeycloakSession session;
    private final Map<String, SignatureVerifierContext> verifiers;

    public KeyAttestationTrustStore(KeycloakSession session) {
        this.session = session;
        this.verifiers = new ConcurrentHashMap<>();
        initializeTrustStore();
    }

    /**
     * Gets a verifier for the specified algorithm.
     *
     * @param algorithm The signature algorithm
     * @return Optional verifier context
     */
    public Optional<SignatureVerifierContext> getVerifier(String algorithm) {
        return Optional.ofNullable(verifiers.get(algorithm));
    }

    private void initializeTrustStore() {
        String trustedKeysJson = session.getContext().getRealm().getAttribute("key_attestation_trusted_keys");
        if (trustedKeysJson == null || trustedKeysJson.isEmpty()) {
            return; // No trusted keys configured
        }

        try {
            List<JWK> trustedKeys = JsonSerialization.mapper.readValue(trustedKeysJson, new TypeReference<List<JWK>>() {});
            for (JWK jwk : trustedKeys) {
                String alg = jwk.getAlgorithm();
                if (alg != null) {
                    SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, alg);
                    if (signatureProvider != null) {
                        SignatureVerifierContext verifier = signatureProvider.verifier(String.valueOf(jwk));
                        if (verifier != null) {
                            verifiers.put(alg, verifier);
                        }
                    }
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to load trusted keys for key attestation", e);
        } catch (VerificationException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void close() {
        // Clean up resources if needed
        verifiers.clear();
    }
}
