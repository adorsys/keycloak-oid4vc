package org.keycloak.protocol.oidc.mappers;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.representations.AccessToken;

public interface OIDCVerifiableCredentials {

    VerifiableCredential transformVerifiableCredential(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session,
                                                       UserSessionModel userSession, ClientSessionContext clientSessionCtx);
}
