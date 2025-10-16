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

package org.keycloak.protocol.oid4vc.issuance.credentialbuilder;

import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.protocol.oid4vc.issuance.TimeProvider;
import org.keycloak.protocol.oid4vc.model.CredentialBuildConfig;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.representations.JsonWebToken;

import java.time.Instant;
import java.util.Optional;
import org.keycloak.protocol.oid4vc.issuance.TimeClaimNormalizer;
import org.keycloak.models.KeycloakSession;

public class JwtCredentialBuilder implements CredentialBuilder {

    private static final String VC_CLAIM_KEY = "vc";
    private static final String ID_CLAIM_KEY = "id";

    private final TimeProvider timeProvider;
    private final KeycloakSession session;

    public JwtCredentialBuilder(TimeProvider timeProvider) {
        this.timeProvider = timeProvider;
        this.session = null;
    }

    public JwtCredentialBuilder(TimeProvider timeProvider, KeycloakSession session) {
        this.timeProvider = timeProvider;
        this.session = session;
    }

    @Override
    public String getSupportedFormat() {
        return Format.JWT_VC;
    }

    @Override
    public JwtCredentialBody buildCredentialBody(
            VerifiableCredential verifiableCredential,
            CredentialBuildConfig credentialBuildConfig
    ) throws CredentialBuilderException {
        // Populate the issuer field of the VC
        verifiableCredential.setIssuer(credentialBuildConfig.getCredentialIssuer());

        // Get the issuance date from the credential. Since nbf is mandatory, we set it to the current time if not
        // provided
        Instant issuanceInstant = Optional.ofNullable(verifiableCredential.getIssuanceDate())
                .orElse(Instant.ofEpochSecond(timeProvider.currentTimeSeconds()));
        Instant normalizedIssuance = session == null ? issuanceInstant : new TimeClaimNormalizer(session)
                .normalize(issuanceInstant, Instant.ofEpochSecond(timeProvider.currentTimeSeconds()));
        long iat = normalizedIssuance.getEpochSecond();

        // set mandatory fields
        JsonWebToken jsonWebToken = new JsonWebToken()
                .issuer(verifiableCredential.getIssuer().toString())
                .nbf(iat)
                .id(CredentialBuilderUtils.createCredentialId(verifiableCredential));
        jsonWebToken.setOtherClaims(VC_CLAIM_KEY, verifiableCredential);

        // expiry is optional
        Optional.ofNullable(verifiableCredential.getExpirationDate())
                .map(exp -> session == null ? exp : new TimeClaimNormalizer(session)
                        .normalize(exp, Instant.ofEpochSecond(timeProvider.currentTimeSeconds())))
                .ifPresent(d -> jsonWebToken.exp(d.getEpochSecond()));

        // subject id should only be set if the credential subject has an id.
        Optional.ofNullable(
                        verifiableCredential
                                .getCredentialSubject()
                                .getClaims()
                                .get(ID_CLAIM_KEY))
                .map(Object::toString)
                .ifPresent(jsonWebToken::subject);

        JWSBuilder.EncodingBuilder jwsBuilder = new JWSBuilder()
                .type(credentialBuildConfig.getTokenJwsType())
                .jsonContent(jsonWebToken);

        return new JwtCredentialBody(jwsBuilder);
    }
}
