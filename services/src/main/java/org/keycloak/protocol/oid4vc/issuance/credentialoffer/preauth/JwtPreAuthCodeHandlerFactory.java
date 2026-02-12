package org.keycloak.protocol.oid4vc.issuance.credentialoffer.preauth;

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.OffsetTimeProvider;

public class JwtPreAuthCodeHandlerFactory implements PreAuthCodeHandlerFactory {

    public static final String PROVIDER_ID = "jwt-pre-auth-code-handler";


    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public JwtPreAuthCodeHandler create(KeycloakSession session) {
        return new JwtPreAuthCodeHandler(session, new OffsetTimeProvider());
    }
}
