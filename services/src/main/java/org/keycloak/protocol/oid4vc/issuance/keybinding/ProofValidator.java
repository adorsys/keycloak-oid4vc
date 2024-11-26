package org.keycloak.protocol.oid4vc.issuance.keybinding;

import org.keycloak.jose.jwk.JWK;
import org.keycloak.protocol.oid4vc.issuance.VCIssuanceContext;
import org.keycloak.protocol.oid4vc.issuance.VCIssuerException;
import org.keycloak.provider.Provider;

public interface ProofValidator extends Provider {

    @Override
    default void close() {
    }

    /**
     * Validates a client-provided key binding proof.
     *
     * @param vcIssuanceContext the issuance context with credential request and config
     * @return the JWK to bind to the credential
     */
    JWK validateProof(VCIssuanceContext vcIssuanceContext) throws VCIssuerException;
}
