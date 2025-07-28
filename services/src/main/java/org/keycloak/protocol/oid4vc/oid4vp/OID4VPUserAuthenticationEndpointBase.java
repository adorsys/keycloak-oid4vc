/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.protocol.oid4vc.oid4vp;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.AuthorizationEndpointBase;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.AuthorizeClientUtil;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Base endpoint class handling common routines needed by OpenID4VP routes.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class OID4VPUserAuthenticationEndpointBase extends AuthorizationEndpointBase {

    private static final Logger logger = Logger.getLogger(OID4VPUserAuthenticationEndpointBase.class);

    private static final String AUTH_SESSION_DELIMITER = ".";
    public static final String AUTH_SESSION_EOL_MARKER = "::";

    public OID4VPUserAuthenticationEndpointBase(KeycloakSession session, EventBuilder event) {
        super(session, event);
    }

    /**
     * Authenticates the Keycloak client sending requests.
     */
    protected ClientModel authenticateClient() {
        logger.debugf("Attempting client authentication");
        ClientModel client = AuthorizeClientUtil
                .authorizeClient(session, event, null)
                .getClient();

        // Reject public clients
        if (client.isPublicClient()) {
            String errorMessage = "Public clients are not supported by this implementation";
            logger.errorf(errorMessage);
            throw new ErrorResponseException(
                    OAuthErrorException.UNAUTHORIZED_CLIENT,
                    errorMessage,
                    Response.Status.UNAUTHORIZED
            );
        }

        logger.debugf("Client %s authenticated", client.getClientId());
        return client;
    }

    /**
     * Recovers session from `authSessionId`.
     */
    protected Optional<AuthenticationSessionModel> getAuthSession(ClientModel client, String authSessionId) {
        if (authSessionId == null || !authSessionId.contains(AUTH_SESSION_DELIMITER)) {
            logger.debugf("Invalid authSessionId format: %s. Delimiter '%s' expected",
                    authSessionId, AUTH_SESSION_DELIMITER);
            return Optional.empty();
        }

        String[] authSessionIdParts = authSessionId
                .split(Pattern.quote(AUTH_SESSION_DELIMITER));

        String rootAuthSessionId = authSessionIdParts[0];
        String tabSessionId = authSessionIdParts[1];

        RootAuthenticationSessionModel rootAuthSession = session.authenticationSessions()
                .getRootAuthenticationSession(realm, rootAuthSessionId);

        if (rootAuthSession == null) {
            return Optional.empty();
        }

        return Optional.of(rootAuthSession.getAuthenticationSession(client, tabSessionId));
    }

    /**
     * Creates new authentication session.
     */
    protected AuthenticationSessionModel createAuthSession(ClientModel client) {
        AuthenticationSessionModel authSession = new AuthenticationSessionManager(session)
                .createAuthenticationSession(realm, false)
                .createAuthenticationSession(client);

        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authSession.setAction(AuthenticatedClientSessionModel.Action.AUTHENTICATE.name());

        return authSession;
    }

    /**
     * Extracts the unique identifier to recover authentication sessions.
     * <p></p>
     * This method prunes any additional information appended to the auth session ID
     * based on the EOL marker. This is to done to allow application code to append
     * additional information to the auth session ID, such as a request or transaction ID,
     * without affecting this session recovery.
     */
    protected static String pruneAuthSessionId(String authSessionId) {
        // Strip all characters from the EOL marker onward.
        int markerIndex = authSessionId.indexOf(AUTH_SESSION_EOL_MARKER);
        if (markerIndex != -1) {
            return authSessionId.substring(0, markerIndex);
        }

        return authSessionId; // Return as is if no EOL marker found
    }

    /**
     * Returns a unique identifier to recover the authentication session.
     */
    public static String getAuthSessionId(AuthenticationSessionModel authSession) {
        String rootAuthSessionId = authSession.getParentSession().getId();
        String tabSessionId = authSession.getTabId();
        return rootAuthSessionId + AUTH_SESSION_DELIMITER + tabSessionId;
    }
}
