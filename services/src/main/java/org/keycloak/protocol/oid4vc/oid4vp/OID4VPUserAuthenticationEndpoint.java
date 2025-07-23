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

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.AuthorizationEndpointBase;
import org.keycloak.services.cors.Cors;
import org.keycloak.services.resource.RealmResourceProvider;

/**
 * Endpoint class for user authentication over
 * <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html">
 * OpenID4VP
 * </a>.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class OID4VPUserAuthenticationEndpoint extends AuthorizationEndpointBase implements RealmResourceProvider {

    private static final Logger logger = Logger.getLogger(OID4VPUserAuthenticationEndpoint.class);

    private Cors cors;

    public OID4VPUserAuthenticationEndpoint(KeycloakSession session, EventBuilder event) {
        super(session, event);
    }

    @Path("")
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public Response getAuthenticationRequestLink() {
        cors = Cors.builder().auth().allowedMethods("GET").auth().exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS);

        logger.trace("Initiating user authentication over OpenID4VP...");
        event.event(EventType.OID4VP_INIT_AUTH);

        // Implement the logic for handling user authentication over OpenID4VP here.
        // This is a placeholder implementation and should be replaced with actual logic.

        return cors.add(Response.ok().entity("User authentication request handled successfully"));
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
    }
}
