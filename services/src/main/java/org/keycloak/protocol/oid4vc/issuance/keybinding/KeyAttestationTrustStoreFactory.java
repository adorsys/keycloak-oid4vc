package org.keycloak.protocol.oid4vc.issuance.keybinding;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderFactory;

/**
 * Factory for KeyAttestationTrustStore provider.
 */
public class KeyAttestationTrustStoreFactory implements ProviderFactory<KeyAttestationTrustStore> {

    @Override
    public String getId() {
        return "key-attestation-trust-store";
    }

    @Override
    public KeyAttestationTrustStore create(KeycloakSession session) {
        return new KeyAttestationTrustStore(session);
    }

    @Override
    public void init(Config.Scope config) {
        // No configuration needed
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-initialization needed
    }

    @Override
    public void close() {
        // No resources to close
    }
}
