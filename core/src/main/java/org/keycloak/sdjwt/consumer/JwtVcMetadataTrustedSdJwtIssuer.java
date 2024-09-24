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

package org.keycloak.sdjwt.consumer;

import org.keycloak.common.VerificationException;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.sdjwt.IssuerSignedJWT;

import java.util.regex.Pattern;

/**
 * A trusted Issuer for running SD-JWT VP verification.
 *
 * <p>
 * This implementation targets issuers exposing verifying keys on a normalized JWT VC Issuer metadata endpoint.
 * </p>
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-05#name-issuer-signed-jwt-verificat">
 * JWT VC Issuer Metadata
 * </a>
 */
public class JwtVcMetadataTrustedSdJwtIssuer implements TrustedSdJwtIssuer {

    private final Pattern issuerUriPattern;

    /**
     * Constructor
     * @param issuerUriPattern a regex pattern for trusted issuers
     */
    public JwtVcMetadataTrustedSdJwtIssuer(String issuerUriPattern) {
        this.issuerUriPattern = Pattern.compile(issuerUriPattern);
    }

    @Override
    public SignatureVerifierContext resolveIssuerVerifyingKey(IssuerSignedJWT issuerSignedJWT)
            throws VerificationException {
        throw new UnsupportedOperationException();
    }
}
