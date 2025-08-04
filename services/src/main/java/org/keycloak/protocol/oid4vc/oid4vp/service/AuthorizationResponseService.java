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
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import org.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import org.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import org.keycloak.protocol.oid4vc.oid4vp.model.dto.ProcessingError;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.MediaType;

import java.util.Base64;

/**
 * Dedicated service for processing OpenID4VP authorization responses for user authentication.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class AuthorizationResponseService {

    private static final Logger logger = Logger.getLogger(AuthorizationResponseService.class);

    private static final String JSON_PATH_ROOT = "$";

    private final KeycloakSession session;

    public AuthorizationResponseService(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Processes authorization response for user authentication.
     */
    public AuthorizationContext processAuthorizationResponse(
            ResponseObject responseObject,
            AuthorizationContext authContext,
            AuthenticationSessionModel authSession
    ) {
        logger.debug("Processing authorization response for user authentication...");
        AuthenticationSessionStore store = new AuthenticationSessionStore(authSession);

        // Validate that authorization context is still open
        if (authContext.getStatus().equals(AuthorizationContextStatus.SUCCESS)) {
            throw failAsBadRequest(
                    ProcessingError.AUTH_CONTEXT_CLOSED,
                    "Authorization context is already closed. Cannot process further responses",
                    authContext, store
            );
        }

        // Extract SD-JWT VP token from the response object
        SdJwtVP sdJwtVp = extractSdJwtVpToken(responseObject, authContext, store);
        logger.debugf("Extracted SD-JWT VP token: %s", sdJwtVp.toString());

        // Formally, we should then check that the VP token satisfies the constraints of
        // the OpenID4VP presentation definition. Equivalently, we offload this task to
        // the SD-JWT authenticator in the authentication flow.

        // Pursue creation process
        return authContext;
    }

    /**
     * Extract SD-JWT VP token from response object
     */
    private SdJwtVP extractSdJwtVpToken(
            ResponseObject responseObject,
            AuthorizationContext authContext,
            AuthenticationSessionStore store
    ) {
        // Ensure that the presentation submission matches the expected presentation definition
        var definition = authContext.getRequestObject().getPresentationDefinition();
        var submission = responseObject.getPresentationSubmission();
        if (!definition.getId().equals(submission.getDefinitionId())
                || definition.getInputDescriptors().size() != submission.getDescriptorMap().size()) {
            throw failAsBadRequest(
                    ProcessingError.INVALID_PRESENTATION_SUBMISSION,
                    "Presentation submission does not match the expected presentation definition",
                    authContext, store
            );
        }

        // Check that the submission's descriptor is of SD-JWT VP format
        var descriptor = submission.getDescriptorMap().getFirst();
        if (!descriptor.getFormat().value().equals(Format.SD_JWT_VC)) {
            throw failAsBadRequest(
                    ProcessingError.INVALID_PRESENTATION_SUBMISSION,
                    "SD-JWT VP token expected, but received: " + descriptor.getFormat().value(),
                    authContext, store
            );
        }

        // Minimalistic JSON path parse. We should normally follow the JSON path provided to
        // extract the SD-JWT VP token as decided by the wallet. However, in this situation,
        // most implementations will simply use the root path "$", enabling us to avoid full
        // JSON path parsing and to bring in a dependency on a JSON path library.
        if (!JSON_PATH_ROOT.equals(descriptor.getPath())) {
            throw failAsBadRequest(
                    ProcessingError.INVALID_PRESENTATION_SUBMISSION,
                    String.format("Invalid path in presentation submission descriptor: %s. Only '%s' is supported",
                            descriptor.getPath(), JSON_PATH_ROOT),
                    authContext, store
            );
        }

        // Check that a vp_token was submitted
        if (responseObject.getVpToken() == null || responseObject.getVpToken().isEmpty()) {
            throw failAsBadRequest(
                    ProcessingError.INVALID_PRESENTATION_SUBMISSION,
                    "Could not parse submission in search for SD-JWT VP token",
                    authContext, store
            );
        }

        try {
            String vpToken = responseObject.getVpToken();
            return SdJwtVP.of(decodeIfBase64Url(vpToken));
        } catch (IllegalArgumentException e) {
            logger.errorf(e, "Failed to parse SD-JWT VP token");
            throw failAsBadRequest(
                    ProcessingError.INVALID_VP_TOKEN,
                    "Could not parse `vp_token` as an SD-JWT VP token",
                    authContext, store
            );
        }
    }

    /**
     * Helper method for repetitive BadRequestException construction.
     */
    private BadRequestException failAsBadRequest(
            ProcessingError error,
            String message,
            AuthorizationContext authorizationContext,
            AuthenticationSessionStore store
    ) {
        logger.errorf("%s: %s", error, message);

        var errorResponse = new OAuth2ErrorRepresentation(error.getErrorString(), message);
        var exception = new BadRequestException(Response
                .status(Response.Status.BAD_REQUEST)
                .entity(errorResponse)
                .type(MediaType.APPLICATION_JSON)
                .build()
        );

        // Update the authorization context with error details
        authorizationContext
                .setStatus(AuthorizationContextStatus.ERROR)
                .setError(error)
                .setErrorDescription(message);
        store.storeAuthorizationContext(authorizationContext);

        return exception;
    }

    /**
     * Helper method to decode Base64URL encoded strings if applicable.
     * If the input is not Base64URL encoded, it returns the input as is.
     */
    private static String decodeIfBase64Url(String input) {
        try {
            // Try to decode as Base64URL
            byte[] decoded = Base64.getUrlDecoder().decode(input);
            return new String(decoded);
        } catch (IllegalArgumentException e) {
            // Not valid Base64URL, return as is
            return input;
        }
    }
}
