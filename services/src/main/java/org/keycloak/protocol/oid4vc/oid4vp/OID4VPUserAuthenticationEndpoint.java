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

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import org.keycloak.protocol.oid4vc.oid4vp.service.AuthenticationSessionStore;
import org.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationRequestService;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Endpoint class for user authentication over
 * <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html">
 * OpenID4VP
 * </a>.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class OID4VPUserAuthenticationEndpoint extends OID4VPUserAuthenticationEndpointBase
        implements RealmResourceProvider {

    private static final Logger logger = Logger.getLogger(OID4VPUserAuthenticationEndpoint.class);

    public static final String REQUEST_JWT_PATH = "/request.jwt";
    public static final String RESPONSE_URI_PATH = "/response";

    private final AuthorizationRequestService authorizationRequestService;

    public OID4VPUserAuthenticationEndpoint(KeycloakSession session, EventBuilder event) {
        super(session, event);
        this.authorizationRequestService = new AuthorizationRequestService(session);
    }

    /**
     * Generates an OpenID4VP authentication request for user authentication.
     */
    @GET
    @Path("/request")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAuthenticationRequest() {
        logger.debug("Initiating user authentication over OpenID4VP...");
        event.event(EventType.OID4VP_INIT_AUTH);

        AuthenticationSessionModel authSession = createAuthSession();

        // Call delegate service to create an authorization request
        AuthorizationContext authorizationContext = authorizationRequestService
                .createAuthorizationRequest(authSession);

        AuthorizationContext reducedContext = new AuthorizationContext()
                .setAuthorizationRequest(authorizationContext.getAuthorizationRequest())
                .setTransactionId(authorizationContext.getTransactionId());

        return Response.ok(reducedContext).build();
    }

    /**
     * Deferences request URIs into signed request objects.
     */
    @GET
    @Path(REQUEST_JWT_PATH + "/{requestId}")
    @Produces(MediaType.TEXT_PLAIN)
    public Response getSignedRequestObject(String requestId) {
        logger.debug("Resolving request URI to signed request object...");

        String authSessionId = pruneAuthSessionId(requestId);
        AuthenticationSessionModel authSession = getAuthSession(authSessionId)
                .orElseThrow(() -> new NotFoundException(
                        "No authentication session attached to request ID: " + requestId
                ));

        AuthorizationContext authorizationContext;
        try {
            authorizationContext = new AuthenticationSessionStore(authSession)
                    .getAuthorizationContextByRequestId(requestId);
        } catch (IllegalArgumentException e) {
            throw new NotFoundException("Authorization context not found for request ID: " + requestId, e);
        }

        String requestObjectJwt = authorizationContext.getRequestObjectJwt();
        return Response.ok(requestObjectJwt).build();
    }

    /**
     * Processes authentication responses from the wallet toward user authentication.
     */
    @POST
    @Path(RESPONSE_URI_PATH)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response processAuthorizationResponse() {
        logger.debug("Processing authorization response for user authentication...");
        return Response.noContent().build();
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
    }
}
