package org.keycloak.protocol.oid4vc.issuance.credentialoffer.preauth;

import static org.keycloak.protocol.oid4vc.issuance.credentialoffer.CredentialOfferStorage.CredentialOfferState;

/**
 * Implementation of {@link PreAuthCodeHandler} for JWT pre-authorized codes.
 */
public class JwtPreAuthCodeHandler implements PreAuthCodeHandler {

    @Override
    public String generatePreAuthCode(CredentialOfferState offerState) {
        return "";
    }

    @Override
    public CredentialOfferState verifyPreAuthCode(String preAuthCode) {
        return null;
    }

    @Override
    public void close() {
    }
}
