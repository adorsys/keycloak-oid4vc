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

package org.keycloak.protocol.oid4vc.oid4vp.service;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import org.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import org.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import org.keycloak.protocol.oid4vc.oid4vp.model.dto.ProcessingError;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.MediaType;

/**
 * Dedicated service for processing OpenID4VP authorization responses for user authentication.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class AuthorizationResponseService {

    private static final Logger logger = Logger.getLogger(AuthorizationResponseService.class);

    private final KeycloakSession session;

    public AuthorizationResponseService(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Processes authorization response for user authentication.
     */
    public AuthorizationContext processAuthorizationResponse(
            ResponseObject responseObject,
            AuthorizationContext authorizationContext,
            AuthenticationSessionModel authSession
    ) {
        logger.debug("Processing authorization response for user authentication...");

        // Validate that authorization context is still open
        if (authorizationContext.getStatus().equals(AuthorizationContextStatus.CLOSED)) {
            failThrowingBadRequest(
                    ProcessingError.AUTH_CONTEXT_CLOSED,
                    "Authorization context is already closed. Cannot process further responses."
            );
        }

        // Extract SD-JWT VP token from the response object
        SdJwtVP sdJwtVp = extractSdJwtVpToken(responseObject, authorizationContext);
        logger.debugf("Extracted SD-JWT VP token: %s", sdJwtVp.toString());

        // Pursue creation process
        return authorizationContext;
    }

    /**
     * Extract SD-JWT VP token from response object
     */
    private SdJwtVP extractSdJwtVpToken(
            ResponseObject responseObject,
            AuthorizationContext authorizationContext
    ) {
        if (responseObject.getVpToken() == null || responseObject.getVpToken().isEmpty()) {
            failThrowingBadRequest(
                    ProcessingError.INVALID_PRESENTATION_SUBMISSION,
                    "Could not parse submission in search for SD-JWT VP token."
            );
        }

        var vpToken = responseObject.getVpToken();
        var presentationSubmission = responseObject.getPresentationSubmission();

        return SdJwtVP.of(vpToken);
    }

    /**
     * Helper method to throw a BadRequestException with a specific error message.
     */
    private void failThrowingBadRequest(ProcessingError error, String message) {
        logger.errorf("%s: %s", error, message);
        var errorResponse = new OAuth2ErrorRepresentation(error.getErrorString(), message);

        throw new BadRequestException(Response
                .status(Response.Status.BAD_REQUEST)
                .entity(errorResponse)
                .type(MediaType.APPLICATION_JSON)
                .build()
        );
    }
}
