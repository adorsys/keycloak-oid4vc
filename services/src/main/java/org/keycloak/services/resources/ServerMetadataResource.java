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
package org.keycloak.services.resources;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.protocol.oauth2.OAuth2WellKnownProviderFactory;
import org.keycloak.constants.Oid4VciConstants;
import org.keycloak.services.cors.Cors;
import static org.keycloak.utils.MediaType.APPLICATION_JWT;

@Provider
@Path("/.well-known")
public class ServerMetadataResource {

    protected static final Logger logger = Logger.getLogger(ServerMetadataResource.class);

    @Context
    protected KeycloakSession session;

    public static UriBuilder wellKnownOAuthProviderUrl(UriBuilder builder) {
        return builder.path(ServerMetadataResource.class).path("{provider}/realms/{realm}");
    }

    @OPTIONS
    @Path("{provider}/realms/{realm}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getOAuth2AuthorizationServerWellKnownVersionPreflight(
            final @PathParam("provider") String providerName,
            final @PathParam("realm") String name) {

        if (!isValidProvider(providerName)) {
            throw new NotFoundException();
        }
        return Cors.builder().allowedMethods("GET").preflight().auth().add(Response.ok());
    }

    @GET
    @Path("{provider}/realms/{realm}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getOAuth2AuthorizationServerWellKnown(
            final @PathParam("provider") String providerName,
            final @PathParam("realm") String name) {

        if (!isValidProvider(providerName)) {
            throw new NotFoundException();
        }

        if (Oid4VciConstants.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER.equals(providerName)) {
            String accept = session.getContext().getRequestHeaders().getHeaderString(HttpHeaders.ACCEPT);
            if (APPLICATION_JWT.equals(accept)) {
                RealmModel realm = new RealmManager(session).getRealmByName(name);
                if (realm != null) {
                    String signed = realm.getAttribute("signed_metadata");
                    if (signed != null && !signed.isEmpty()) {
                        return Cors.builder().allowAllOrigins().auth()
                                .add(Response.ok(signed).header(HttpHeaders.CONTENT_TYPE, APPLICATION_JWT));
                    }
                }
            }
        }
        return RealmsResource.getWellKnownResponse(session, name, providerName, logger);
    }

    private boolean isValidProvider(String providerName) {
        // you can add codes here considering the current status of the implementation (preview, experimental).
        return OAuth2WellKnownProviderFactory.PROVIDER_ID.equals(providerName)
                || Oid4VciConstants.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER.equals(providerName);
    }
}
