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

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.jose.jwe.JWEUtils;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.oid4vp.model.ClientIdScheme;
import org.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import org.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import org.keycloak.protocol.oid4vc.oid4vp.model.ResponseMode;
import org.keycloak.protocol.oid4vc.oid4vp.model.ResponseType;
import org.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import org.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationDefinition;

import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Dedicated service for creating OpenID4VP authorization requests for user authentication.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class AuthorizationRequestService {

    private static final Logger logger = Logger.getLogger(AuthorizationRequestService.class);


    public static final String VCT_CONFIG_DEFAULT = "https://credentials.example.com/identity_credential";
    public static final int SECURE_RANDOM_ENTROPY = 20;

    // Note: "https://self-issued.me/v2" is a symbolic string and can be used
    // as an aud Claim value even when this specification is used standalone,
    // without SIOPv2.
    public static final String SYMBOLIC_AUD = "https://self-issued.me/v2";

    private final SdJwtCredentialPresenter sdJwtCredentialPresenter = new SdJwtCredentialPresenter();
    private final ClientMetadata clientMetadata;
    private final Map<String, String> sessionStore;

    public AuthorizationRequestService(KeycloakSession session, Map<String, String> sessionStore) {
        ClientMetadataDiscoveryService clientMetadataService = new ClientMetadataDiscoveryService(session);
        this.clientMetadata = clientMetadataService.getClientMetadata();
        this.sessionStore = sessionStore;
    }

    /**
     * Creates a fresh authorization request for user authentication.
     */
    public AuthorizationContext createAuthorizationRequest() {
        logger.info("Creating a fresh authorization request for user authentication...");

        // Construct presentation definition
        var presentationDefinition = sdJwtCredentialPresenter
                .generatePresentationDefinition(VCT_CONFIG_DEFAULT, List.of(OAuth2Constants.USERNAME));

        // Pursue creation process
        return concludeAuthorizationRequestOffer(configParams, presentationDefinition);
    }

    /**
     * Generates a cryptographically secure random string.
     */
    public static String generateRandomString() {
        // Generate a cryptographically secure random byte array
        byte[] randomBytes = JWEUtils.generateSecret(20);

        // Convert the random number to a hexadecimal string
        return new BigInteger(1, randomBytes).toString(16);
    }

    /**
     * Concludes authorization request creation from presentation definition.
     */
    private AuthorizationRequestOfferDTO concludeAuthorizationRequestOffer(
            RequestOfferConfigParamsDTO configParams,
            PresentationDefinition presentationDefinition
    ) {

                .state(SecureRandomGenerator.generateRandomString());



        return createAuthorizationRequestLink(templateRequest.build(), configParams);
    }

    /**
     * Returns a starter for building request objects.
     */
    private RequestObject templateRequestObject(PresentationDefinition presentationDefinition) {
        return new RequestObject()
                .setResponseMode(ResponseMode.DIRECT_POST)
                .setResponseType(ResponseType.VP_TOKEN)
                .setClientId(clientMetadata.getClientId())
                .setClientIdScheme(ClientIdScheme.X509_SAN_DNS)
                .setAudience(SYMBOLIC_AUD)
                .setPresentationDefinition(presentationDefinition)
                .setClientMetadata(clientMetadata);
    }

    private AuthorizationRequestOfferDTO createAuthorizationRequestLink(
            RequestObjectDTO requestObjectDTO,
            RequestOfferConfigParamsDTO configParamsDTO
    ) {
        var signed = createRequestObjectJwt(requestObjectDTO, configParamsDTO);

        var clientId = verifierConfig.clientMetadata().getClientId();
        var requestUri = verifierConfig.requestObjectUri() + "/" + signed.getState();

        var link = String.format("openid4vp://authorize?client_id=%s&request_uri=%s",
                URLEncoder.encode(clientId, StandardCharsets.UTF_8),
                URLEncoder.encode(requestUri, StandardCharsets.UTF_8));

        return AuthorizationRequestOfferDTO.builder()
                .transactionId(signed.getTransactionId())
                .requestOfferUri(link)
                .build();
    }

    private SignedRequestObject createRequestObjectJwt(
            RequestObjectDTO requestObject,
            RequestOfferConfigParamsDTO configParamsDTO
    ) {
        log.info("Signing request object ({})", requestObject.getState());

        var requestJwt = jwtSigner.signRequest(requestObject);

        var signed = SignedRequestObject.builder()
                .transactionId(SecureRandomGenerator.generateRandomString())
                .resultUri(configParamsDTO.getResultUri())
                .state(requestObject.getState())
                .requestJwt(requestJwt)
                .build();

        return signedRequestObjectRepository.save(signed);
    }
}
