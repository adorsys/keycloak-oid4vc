/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.protocol.oidc.grants;

import com.fasterxml.jackson.core.type.TypeReference;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.Profile;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.model.AuthorizationDetailResponse;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.utils.OAuth2Code;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.protocol.oid4vc.model.CredentialsOffer;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.MediaType;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public class PreAuthorizedCodeGrantType extends OAuth2GrantTypeBase {

    private static final Logger LOGGER = Logger.getLogger(PreAuthorizedCodeGrantType.class);

    public static final String VC_ISSUANCE_FLOW = "VC-Issuance-Flow";
    private static final String CREDENTIAL_OFFER_KEY_PREFIX = "credential_offer_";

    @Override
    public Response process(Context context) {
        LOGGER.debug("Process grant request for preauthorized.");
        setContext(context);

        // See: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-request
        String code = formParams.getFirst(PreAuthorizedCodeGrantTypeFactory.CODE_REQUEST_PARAM);

        if (code == null) {
            // See: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-request
            String errorMessage = "Missing parameter: " + PreAuthorizedCodeGrantTypeFactory.CODE_REQUEST_PARAM;
            event.detail(Details.REASON, errorMessage);
            event.error(Errors.INVALID_CODE);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                    errorMessage, Response.Status.BAD_REQUEST);
        }
        OAuth2CodeParser.ParseResult result = OAuth2CodeParser.parseCode(session, code, realm, event);
        if (result.isIllegalCode()) {
            event.error(Errors.INVALID_CODE);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT, "Code not valid",
                    Response.Status.BAD_REQUEST);
        }
        if (result.isExpiredCode()) {
            event.error(Errors.EXPIRED_CODE);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT, "Code is expired",
                    Response.Status.BAD_REQUEST);
        }
        AuthenticatedClientSessionModel clientSession = result.getClientSession();
        ClientSessionContext sessionContext = DefaultClientSessionContext.fromClientSessionAndScopeParameter(clientSession,
                OAuth2Constants.SCOPE_OPENID, session);
        clientSession.setNote(VC_ISSUANCE_FLOW, PreAuthorizedCodeGrantTypeFactory.GRANT_TYPE);
        sessionContext.setAttribute(Constants.GRANT_TYPE, PreAuthorizedCodeGrantTypeFactory.GRANT_TYPE);

        // set the client as retrieved from the pre-authorized session
        session.getContext().setClient(result.getClientSession().getClient());

        // Retrieve CredentialsOffer
        CredentialsOffer credentialsOffer = getCredentialsOfferFromSession(clientSession, code);

        // Process authorization_details
        List<AuthorizationDetailResponse> authorizationDetailsResponse = processAuthorizationDetails();

        // Restrict Access Token to the credentials specified in the Credential Offer
        String allowedCredentials = String.join(" ", credentialsOffer.getCredentialConfigurationIds());
        AccessToken accessToken = tokenManager.createClientAccessToken(session,
                clientSession.getRealm(),
                clientSession.getClient(),
                clientSession.getUserSession().getUser(),
                clientSession.getUserSession(),
                sessionContext);

        if (!allowedCredentials.isEmpty()) {
            accessToken.setOtherClaims("allowed_credentials", allowedCredentials);
        }

        // Include authorization_details in the response
        TokenManager.AccessTokenResponseBuilder responseBuilder = tokenManager.responseBuilder(
                clientSession.getRealm(),
                clientSession.getClient(),
                event,
                session,
                clientSession.getUserSession(),
                sessionContext).accessToken(accessToken);

        AccessTokenResponse tokenResponse;
        try {
            tokenResponse = responseBuilder.build();
        } catch (RuntimeException re) {
            if ("can not get encryption KEK".equals(re.getMessage())) {
                throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                        "can not get encryption KEK", Response.Status.BAD_REQUEST);
            } else {
                throw re;
            }
        }

        // If authorization_details is present, serialize the response and add it
        if (authorizationDetailsResponse != null) {
            try {
                Map<String, Object> responseMap = objectMapper.convertValue(tokenResponse, new TypeReference<Map<String, Object>>() {});
                responseMap.put(AUTHORIZATION_DETAILS_PARAM, authorizationDetailsResponse);
                event.success();
                return cors.allowAllOrigins().add(Response.ok(responseMap).type(MediaType.APPLICATION_JSON_TYPE));
            } catch (Exception e) {
                event.error(Errors.INVALID_REQUEST);
                throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                        "Failed to include authorization_details in response", Response.Status.BAD_REQUEST);
            }
        }

        // return the original token response without serialization
        event.success();
        return cors.allowAllOrigins().add(Response.ok(tokenResponse).type(MediaType.APPLICATION_JSON_TYPE));
    }

    @Override
    public EventType getEventType() {
        return EventType.CODE_TO_TOKEN;
    }

    /**
     * Create a pre-authorized Code for the given client session.
     *
     * @param session                    - keycloak session to be used
     * @param authenticatedClientSession - client session to be persisted
     * @param expirationTime             - expiration time of the code, the code should be short-lived
     * @return the pre-authorized code
     */
    public static String getPreAuthorizedCode(KeycloakSession session, AuthenticatedClientSessionModel authenticatedClientSession, int expirationTime) {
        String codeId = UUID.randomUUID().toString();
        String nonce = SecretGenerator.getInstance().randomString();
        OAuth2Code oAuth2Code = new OAuth2Code(codeId, expirationTime, nonce, null, null, null, null, null,
                authenticatedClientSession.getUserSession().getId());
        return OAuth2CodeParser.persistCode(session, authenticatedClientSession, oAuth2Code);
    }

    // Helper method to retrieve CredentialsOffer from client session
    private CredentialsOffer getCredentialsOfferFromSession(AuthenticatedClientSessionModel clientSession, String code) {
        String offerJson = clientSession.getNote(CREDENTIAL_OFFER_KEY_PREFIX + code);
        if (offerJson == null) {
            LOGGER.warnf("No CredentialsOffer found for pre-authorized code: %s", code);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "No credential offer associated with pre-authorized code", Response.Status.BAD_REQUEST);
        }

        try {
            return JsonSerialization.mapper.readValue(offerJson, CredentialsOffer.class);
        } catch (Exception e) {
            LOGGER.warnf("Failed to parse CredentialsOffer for pre-authorized code %s: %s", code, e.getMessage());
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "Invalid credential offer data", Response.Status.BAD_REQUEST);
        } finally {
            // Remove the offer to prevent reuse
            clientSession.removeNote(CREDENTIAL_OFFER_KEY_PREFIX + code);
        }
    }

    // Overloaded method to support CredentialsOffer
    public static String getPreAuthorizedCode(KeycloakSession session, AuthenticatedClientSessionModel authenticatedClientSession, int expirationTime, CredentialsOffer credentialsOffer) {
        String codeId = UUID.randomUUID().toString();
        String nonce = SecretGenerator.getInstance().randomString();
        OAuth2Code oAuth2Code = new OAuth2Code(codeId, expirationTime, nonce, null, null, null, null, null,
                authenticatedClientSession.getUserSession().getId());
        String preAuthorizedCode = OAuth2CodeParser.persistCode(session, authenticatedClientSession, oAuth2Code);

        // Store the CredentialsOffer with the pre-authorized code as the key
        if (credentialsOffer != null) {
            try {
                String offerJson = JsonSerialization.mapper.writeValueAsString(credentialsOffer);
                authenticatedClientSession.setNote(CREDENTIAL_OFFER_KEY_PREFIX + preAuthorizedCode, offerJson);
            } catch (Exception e) {
                LOGGER.warnf("Failed to store CredentialsOffer for pre-authorized code %s: %s", preAuthorizedCode, e.getMessage());
            }
        }

        return preAuthorizedCode;
    }
}
