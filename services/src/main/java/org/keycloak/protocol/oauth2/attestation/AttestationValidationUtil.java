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

package org.keycloak.protocol.oauth2.attestation;

import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.AsymmetricSignatureVerifierContext;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.ServerECDSASignatureVerifierContext;
import org.keycloak.jose.jws.AlgorithmType;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.representations.JsonWebToken;

import java.util.Map;
import java.util.Set;

import java.util.Map;
import java.util.Set;

/**
 * Utility class for validating attestation-based client authentication JWTs.
 */
public class AttestationValidationUtil {

    // Private key component names per RFC 7517
    private static final Set<String> RSA_PRIVATE_COMPONENTS = Set.of("d", "p", "q", "dp", "dq", "qi", "oth");
    private static final Set<String> EC_PRIVATE_COMPONENTS = Set.of("d");
    private static final Set<String> OKP_PRIVATE_COMPONENTS = Set.of("d");

    /**
     * Validates that a JWK contains only public key components (no private key material).
     * 
     * @param jwkMap The JWK as a Map
     * @throws VerificationException if private key components are found
     */
    public static void validateJwkIsPublicKeyOnly(Map<String, Object> jwkMap) throws VerificationException {
        String kty = (String) jwkMap.get("kty");
        if (kty == null) {
            throw new VerificationException("Missing kty in JWK");
        }

        Set<String> privateComponents;
        switch (kty) {
            case "RSA":
                privateComponents = RSA_PRIVATE_COMPONENTS;
                break;
            case "EC":
                privateComponents = EC_PRIVATE_COMPONENTS;
                break;
            case "OKP":
                privateComponents = OKP_PRIVATE_COMPONENTS;
                break;
            default:
                // For unknown key types, check for common private components
                privateComponents = Set.of("d", "p", "q");
                break;
        }

        for (String privateComponent : privateComponents) {
            if (jwkMap.containsKey(privateComponent)) {
                throw new VerificationException("JWK contains private key component: " + privateComponent);
            }
        }
    }

    /**
     * Validates the typ header in a JWT.
     * 
     * @param header The JWS header
     * @param expectedType The expected typ value (e.g., "client-attestation+jwt", "pop+jwt")
     * @throws VerificationException if typ is missing or doesn't match
     */
    public static void validateTypHeader(JWSHeader header, String expectedType) throws VerificationException {
        String typ = header.getType();
        if (typ == null || !typ.equals(expectedType)) {
            throw new VerificationException("Invalid or missing typ header. Expected: " + expectedType + ", got: " + typ);
        }
    }

    /**
     * Validates that the algorithm is asymmetric, supported, and not "none".
     * 
     * @param algorithm The algorithm name
     * @throws VerificationException if algorithm is invalid
     */
    public static void validateAlgorithm(String algorithm) throws VerificationException {
        if (algorithm == null || algorithm.equalsIgnoreCase("none")) {
            throw new VerificationException("Algorithm must be asymmetric and not 'none'");
        }

        try {
            org.keycloak.jose.jws.Algorithm alg = org.keycloak.jose.jws.Algorithm.valueOf(algorithm);
            AlgorithmType type = alg.getType();
            if (type != AlgorithmType.RSA && type != AlgorithmType.ECDSA && type != AlgorithmType.EDDSA) {
                throw new VerificationException("Algorithm must be asymmetric (RSA, ECDSA, or EdDSA)");
            }
        } catch (IllegalArgumentException e) {
            throw new VerificationException("Unsupported algorithm: " + algorithm);
        }
    }

    /**
     * Creates an appropriate signature verifier context based on the algorithm.
     * 
     * @param keyWrapper The key wrapper containing the public key
     * @param algorithm The algorithm name
     * @return The signature verifier context
     */
    public static AsymmetricSignatureVerifierContext createVerifierContext(KeyWrapper keyWrapper, String algorithm) {
        try {
            org.keycloak.jose.jws.Algorithm alg = org.keycloak.jose.jws.Algorithm.valueOf(algorithm);
            AlgorithmType type = alg.getType();
            if (type == AlgorithmType.ECDSA) {
                return new org.keycloak.crypto.ServerECDSASignatureVerifierContext(keyWrapper);
            } else {
                return new AsymmetricSignatureVerifierContext(keyWrapper);
            }
        } catch (IllegalArgumentException e) {
            // Default to asymmetric verifier
            return new AsymmetricSignatureVerifierContext(keyWrapper);
        }
    }

    /**
     * Validates JWT claims (iss, sub, aud, nbf, exp, etc.) using TokenVerifier.
     * 
     * @param tokenString The JWT token string
     * @param expectedIssuer The expected issuer (can be null to skip check)
     * @param expectedSubject The expected subject (can be null to skip check)
     * @param expectedAudience The expected audience (can be null to skip check)
     * @param verifierContext The signature verifier context
     * @return The verified token
     * @throws VerificationException if validation fails
     */
    public static JsonWebToken validateJwtClaims(String tokenString, String expectedIssuer, 
                                                 String expectedSubject, String expectedAudience,
                                                 AsymmetricSignatureVerifierContext verifierContext) throws VerificationException {
        TokenVerifier<JsonWebToken> verifier = TokenVerifier.create(tokenString, JsonWebToken.class)
                .verifierContext(verifierContext);

        if (expectedIssuer != null) {
            verifier.realmUrl(expectedIssuer);
        }
        if (expectedSubject != null) {
            verifier.withChecks(TokenVerifier.SUBJECT_EXISTS_CHECK);
        }
        if (expectedAudience != null) {
            verifier.audience(expectedAudience);
        }

        // Check that token is active (not expired, nbf valid)
        verifier.withChecks(TokenVerifier.IS_ACTIVE);

        JsonWebToken token = verifier.verify().getToken();
        
        // Additional manual check for subject if provided
        if (expectedSubject != null && !expectedSubject.equals(token.getSubject())) {
            throw new VerificationException("Subject mismatch. Expected: " + expectedSubject + ", got: " + token.getSubject());
        }

        return token;
    }

    /**
     * Validates that client_id matches the subject of the attestation JWT and issuer of the PoP JWT.
     * 
     * @param clientId The client ID
     * @param attestationSub The subject from the attestation JWT
     * @param popIss The issuer from the PoP JWT
     * @throws VerificationException if there's a mismatch
     */
    public static void validateClientIdMatches(String clientId, String attestationSub, String popIss) throws VerificationException {
        if (clientId == null || attestationSub == null || popIss == null) {
            throw new VerificationException("Missing required claims for client_id validation");
        }

        if (!clientId.equals(attestationSub)) {
            throw new VerificationException("client_id does not match attestation sub claim");
        }

        if (!clientId.equals(popIss)) {
            throw new VerificationException("client_id does not match PoP iss claim");
        }
    }
}

