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
import org.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Dedicated service for creating OpenID4VP authorization requests for user authentication.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class AuthorizationRequestService {

    private static final Logger logger = Logger.getLogger(AuthorizationRequestService.class);

    // Note: "https://self-issued.me/v2" is a symbolic string and can be used
    // as an aud Claim value even when this specification is used standalone,
    // without SIOPv2.
    public static final String SYMBOLIC_AUD = "https://self-issued.me/v2";

    private final SdJwtCredentialPresenter sdJwtCredentialPresenter = new SdJwtCredentialPresenter();

    /**
     * Creates a fresh authorization request for user authentication.
     */
    public AuthorizationContext createAuthorizationRequest() {
        logger.info("Creating a fresh authorization request for user authentication...");

        // Construct presentation definition
        var presentationDefinition = sdJwtCredentialPresenter
                .generatePresentationDefinition(configParams.getIssuerVct(), configParams.getRequiredClaims());

        // Pursue creation process
        return concludeAuthorizationRequestOffer(configParams, presentationDefinition);
    }

    /**
     * Concludes authorization request creation from presentation definition.
     */
    private AuthorizationRequestOfferDTO concludeAuthorizationRequestOffer(
            RequestOfferConfigParamsDTO configParams,
            PresentationDefinition presentationDefinition
    ) {
        // Build request object for response mode
        EResponseMode responseMode = configParams.getResponseMode();

        var templateRequest = templateRequestObject(presentationDefinition)
                .responseMode(responseMode)
                .state(SecureRandomGenerator.generateRandomString());

        if (EResponseMode.FRAGMENT == responseMode) {
            // Verifier client redirect URI
            templateRequest.redirectUri(configParams.getRedirectUri());
        } else if (EResponseMode.DIRECT_POST == responseMode) {
            templateRequest.responseUri(verifierConfig.responseUri());
        } else {
            throw new UnsupportedOperationException(
                    String.format("Provided response mode %s is not supported", responseMode)
            );
        }

        return createAuthorizationRequestLink(templateRequest.build(), configParams);
    }

    /**
     * Returns a response mode agnostic starter for building request objects.
     */
    private RequestObjectDTO.RequestObjectDTOBuilder templateRequestObject(PresentationDefinition presentationDefinition) {
        return RequestObjectDTO.builder()
                .responseType(EResponseType.VP_TOKEN)
                .clientId(verifierConfig.clientId())
                .clientIdScheme(EClientIdScheme.X509_SAN_DNS)
                .aud(SYMBOLIC_AUD)
                .presentationDefinition(presentationDefinition)
                .clientMetadata(verifierConfig.clientMetadata());
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
