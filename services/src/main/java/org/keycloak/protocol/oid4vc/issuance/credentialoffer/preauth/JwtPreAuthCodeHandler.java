package org.keycloak.protocol.oid4vc.issuance.credentialoffer.preauth;

import org.keycloak.protocol.oid4vc.issuance.TimeProvider;
import org.keycloak.protocol.oid4vc.model.JwtPreAuthCode;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.credentialoffer.CredentialOfferStorage.CredentialOfferState;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProvider;

/**
 * Implementation of {@link PreAuthCodeHandler} for JWT pre-authorized codes.
 */
public class JwtPreAuthCodeHandler implements PreAuthCodeHandler {

    private final KeycloakSession session;
    private final TimeProvider timeProvider;

    public JwtPreAuthCodeHandler(KeycloakSession session, TimeProvider timeProvider) {
        this.session = session;
        this.timeProvider = timeProvider;
    }

    @Override
    public String generatePreAuthCode(CredentialOfferState offerState) {
        JwtPreAuthCode jwtBody = (JwtPreAuthCode) new JwtPreAuthCode()
                .credentialOfferState(offerState)
                .issuedFor(OID4VCIssuerWellKnownProvider.getIssuer(session.getContext()))
                .addAudience("")
                .iat((long) timeProvider.currentTimeSeconds())
                .exp((long) offerState.getExpiration());

        KeyWrapper signingKey = session.keys().getActiveKey(session.getContext().getRealm(), KeyUse.SIG, "ES256");
        SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, signingKey.getAlgorithm());
        SignatureSignerContext signer = signatureProvider.signer(signingKey);
        return new JWSBuilder().jsonContent(jwtBody).sign(signer);
    }

    @Override
    public CredentialOfferState verifyPreAuthCode(String preAuthCode) {
        // TODO: Implement JWT verification and state reconstruction
        return null;
    }

    @Override
    public void close() {
    }
}
