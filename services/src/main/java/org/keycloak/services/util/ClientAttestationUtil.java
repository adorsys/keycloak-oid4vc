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

package org.keycloak.services.util;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import jakarta.ws.rs.core.Response;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.TokenVerifier;
import org.keycloak.common.Profile;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.PublicKeysWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.exceptions.TokenVerificationException;
import org.keycloak.http.HttpRequest;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.keys.PublicKeyLoader;
import org.keycloak.keys.PublicKeyStorageProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.representations.oauth.ClientAttestation;
import org.keycloak.representations.oauth.ClientAttestationPoP;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.cors.Cors;
import org.keycloak.protocol.oidc.utils.JWKSHttpUtils;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.JWKSUtils;


/**
 * Utility class for handling OAuth Client Attestation headers as defined in
 * draft-ietf-oauth-attestation-based-client-auth-07
 *
 * @author <a href="mailto:Forkim.Akwichek@adorsys.com">Forkim Akwichek</a>
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html">OAuth 2.0 Attestation-Based Client Authentication</a>
 */
public class ClientAttestationUtil {

    public static final String CLIENT_ATTESTATION_SESSION_ATTRIBUTE = "client-attestation";
    public static final String CLIENT_ATTESTATION_POP_SESSION_ATTRIBUTE = "client-attestation-pop";

    public static final int DEFAULT_ATTESTATION_LIFETIME = 300;
    public static final int DEFAULT_ALLOWED_CLOCK_SKEW = 15;

    /**
     * If Client Attestation feature is enabled and the current request contains attestation headers,
     * this method validates the attestation and stores it in the session.
     */
    public static void handleClientAttestationHeaders(KeycloakSession keycloakSession,
                                                      EventBuilder event,
                                                      Cors cors) {
        if (!Profile.isFeatureEnabled(Profile.Feature.CLIENT_ATTESTATION)) {
            return;
        }

        HttpRequest request = keycloakSession.getContext().getHttpRequest();

        // Validate exactly one of each header
        List<String> attestationHeaders = request.getHttpHeaders().getRequestHeader(OAuth2Constants.CLIENT_ATTESTATION_HTTP_HEADER);
        List<String> attestationPoPHeaders = request.getHttpHeaders().getRequestHeader(OAuth2Constants.CLIENT_ATTESTATION_POP_HTTP_HEADER);

        if (attestationHeaders == null || attestationHeaders.isEmpty()) {
            return;
        }
        if (attestationHeaders.size() != 1) {
            event.detail(Details.REASON, "Multiple OAuth-Client-Attestation headers found");
            event.error(Errors.INVALID_CLIENT_ATTESTATION);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_CLIENT,
                    "Multiple OAuth-Client-Attestation headers found", Response.Status.BAD_REQUEST);
        }
        if (attestationPoPHeaders == null || attestationPoPHeaders.isEmpty()) {
            return;
        }
        if (attestationPoPHeaders.size() != 1) {
            event.detail(Details.REASON, "Multiple OAuth-Client-Attestation-PoP headers found");
            event.error(Errors.INVALID_CLIENT_ATTESTATION);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_CLIENT,
                    "Multiple OAuth-Client-Attestation-PoP headers found", Response.Status.BAD_REQUEST);
        }

        try {
            ClientAttestation attestation = new ClientAttestationUtil.Validator(keycloakSession)
                    .request(request)
                    .validateAttestation();

            ClientAttestationPoP attestationPoP = new ClientAttestationUtil.Validator(keycloakSession)
                    .request(request)
                    .attestation(attestation)
                    .validateAttestationPoP();

            // Validate client_id matches request parameter if present 
            validateClientIdMatch(request, attestation, attestationPoP);

            keycloakSession.setAttribute(CLIENT_ATTESTATION_SESSION_ATTRIBUTE, attestation);
            keycloakSession.setAttribute(CLIENT_ATTESTATION_POP_SESSION_ATTRIBUTE, attestationPoP);
        } catch (ClientAttestationChallengeException ex) {
            event.detail(Details.REASON, ex.getMessage());
            event.error(Errors.USE_ATTESTATION_CHALLENGE);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_CLIENT,
                    "use_attestation_challenge", Response.Status.BAD_REQUEST);
        } catch (ClientAttestationFreshnessException ex) {
            event.detail(Details.REASON, ex.getMessage());
            event.error(Errors.USE_FRESH_ATTESTATION);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_CLIENT,
                    "use_fresh_attestation", Response.Status.BAD_REQUEST);
        } catch (VerificationException ex) {
            event.detail(Details.REASON, ex.getMessage());
            event.error(Errors.INVALID_CLIENT_ATTESTATION);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_CLIENT,
                    ex.getMessage(), Response.Status.BAD_REQUEST);
        }
    }

    private static ClientAttestation validateClientAttestation(KeycloakSession session, String token) throws VerificationException {
        if (token == null || token.trim().isEmpty()) {
            throw new VerificationException("Client Attestation is missing");
        }

        TokenVerifier<ClientAttestation> verifier = TokenVerifier.create(token, ClientAttestation.class);
        JWSHeader header;

        try {
            header = verifier.getHeader();
        } catch (VerificationException ex) {
            throw new VerificationException("Client Attestation header verification failure");
        }

        if (!ClientAttestation.TYPE.equals(header.getType())) {
            throw new VerificationException("Invalid or missing type in Client Attestation header: " + header.getType());
        }

        String algorithm = header.getAlgorithm().name();

        if (!getClientAttestationSupportedAlgorithms(session).contains(algorithm)) {
            throw new VerificationException("Unsupported Client Attestation algorithm: " + header.getAlgorithm());
        }

        // Validate algorithm is asymmetric
        SignatureProvider provider = session.getProvider(SignatureProvider.class, algorithm);
        if (provider == null || !provider.isAsymmetricAlgorithm()) {
            throw new VerificationException("Client Attestation algorithm must be asymmetric: " + algorithm);
        }

        ClientAttestation attestation;
        try {
            // Parse the JWT payload to get claims without signature verification
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                throw new VerificationException("Invalid JWT format");
            }

            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));

            // Create a temporary ClientAttestation object from the payload for expiration check
            attestation = JsonSerialization.readValue(payload, ClientAttestation.class);

        } catch (Exception e) {
            throw new VerificationException("Failed to parse Client Attestation for expiration check: " + e.getMessage(), e);
        }

        // Check expiration before doing expensive signature verification
        if (!attestation.isActive(DEFAULT_ALLOWED_CLOCK_SKEW)) {
            throw new VerificationException("Client Attestation has expired");
        }

        // Check not-before time if present
        if (attestation.getNotBefore() != null && attestation.getNotBefore() > Time.currentTime() + DEFAULT_ALLOWED_CLOCK_SKEW) {
            throw new VerificationException("Client Attestation is not yet valid");
        }

        // Now perform signature verification against trusted attester's key
        verifyAttesterSignature(session, verifier, token);

        try {
            // Verify the signature and get the final attestation
            attestation = verifier.verify().getToken();

            // Validate required claims
            validateClientAttestationClaims(attestation);

            // Validate attestation freshness
            validateAttestationFreshness(attestation);

            return attestation;
        } catch (VerificationException ex) {
            throw new VerificationException("Client Attestation verification failure: " + ex.getMessage(), ex);
        }
    }

    private static void validateClientAttestationClaims(ClientAttestation attestation) throws VerificationException {
        // Validate required claims
        if (attestation.getIssuer() == null || attestation.getIssuer().trim().isEmpty()) {
            throw new VerificationException("Client Attestation missing required 'iss' claim");
        }

        if (attestation.getSubject() == null || attestation.getSubject().trim().isEmpty()) {
            throw new VerificationException("Client Attestation missing required 'sub' claim");
        }

        if (attestation.getExp() == null) {
            throw new VerificationException("Client Attestation missing required 'exp' claim");
        }

        if (attestation.getConfirmation() == null || attestation.getConfirmation().getJwk() == null) {
            throw new VerificationException("Client Attestation missing required 'cnf' claim with JWK");
        }

        // Validate expiration time
        if (!attestation.isActive(DEFAULT_ALLOWED_CLOCK_SKEW)) {
            throw new VerificationException("Client Attestation has expired");
        }

        // Validate not-before time if present
        if (attestation.getNotBefore() != null && attestation.getNotBefore() > Time.currentTime() + DEFAULT_ALLOWED_CLOCK_SKEW) {
            throw new VerificationException("Client Attestation is not yet valid");
        }
    }

    private static ClientAttestationPoP validateClientAttestationPoP(KeycloakSession session,
                                                                     String token,
                                                                     ClientAttestation attestation) throws VerificationException {
        if (token == null || token.trim().isEmpty()) {
            throw new VerificationException("Client Attestation PoP is missing");
        }

        TokenVerifier<ClientAttestationPoP> verifier = TokenVerifier.create(token, ClientAttestationPoP.class);
        JWSHeader header;

        try {
            header = verifier.getHeader();
        } catch (VerificationException ex) {
            throw new VerificationException("Client Attestation PoP header verification failure");
        }

        if (!ClientAttestationPoP.TYPE.equals(header.getType())) {
            throw new VerificationException("Invalid or missing type in Client Attestation PoP header: " + header.getType());
        }

        String algorithm = header.getAlgorithm().name();

        if (!getClientAttestationSupportedAlgorithms(session).contains(algorithm)) {
            throw new VerificationException("Unsupported Client Attestation PoP algorithm: " + header.getAlgorithm());
        }

        // Validate algorithm is asymmetric
        SignatureProvider provider = session.getProvider(SignatureProvider.class, algorithm);
        if (provider == null || !provider.isAsymmetricAlgorithm()) {
            throw new VerificationException("Client Attestation PoP algorithm must be asymmetric: " + algorithm);
        }

        // Verify signature using the key from the Client Attestation
        if (attestation.getConfirmation() != null && attestation.getConfirmation().getJwk() != null) {
            try {
                // Extract JWK from attestation and create verifier
                Object jwkObj = attestation.getConfirmation().getJwk();
                JWK jwk;

                if (jwkObj instanceof JWK) {
                    // JWK is already a JWK object
                    jwk = (JWK) jwkObj;
                } else if (jwkObj instanceof Map) {
                    // JWK is stored as a Map, convert to JWK object
                    Map<String, Object> jwkMap = (Map<String, Object>) jwkObj;
                    jwk = JsonSerialization.readValue(
                            JsonSerialization.writeValueAsBytes(jwkMap),
                            JWK.class
                    );
                } else {
                    throw new VerificationException("Invalid JWK format in Client Attestation");
                }

                KeyWrapper keyWrapper = JWKSUtils.getKeyWrapper(jwk);

                if (keyWrapper.getPublicKey() == null) {
                    throw new VerificationException("No public key in Client Attestation JWK");
                }
                if (keyWrapper.getPrivateKey() != null) {
                    throw new VerificationException("Private key is present in Client Attestation JWK");
                }

                keyWrapper.setAlgorithm(algorithm);
                SignatureVerifierContext signatureVerifier = session.getProvider(SignatureProvider.class, algorithm).verifier(keyWrapper);
                verifier.verifierContext(signatureVerifier);
            } catch (Exception ex) {
                throw new VerificationException("Failed to verify Client Attestation PoP signature: " + ex.getMessage(), ex);
            }
        } else {
            throw new VerificationException("Client Attestation missing JWK for PoP verification");
        }

        try {
            ClientAttestationPoP attestationPoP = verifier.verify().getToken();

            // Validate required claims
            validateClientAttestationPoPClaims(attestationPoP, attestation, session);

            return attestationPoP;
        } catch (VerificationException ex) {
            throw new VerificationException("Client Attestation PoP verification failure: " + ex.getMessage(), ex);
        }
    }

    private static void validateClientAttestationPoPClaims(ClientAttestationPoP attestationPoP,
                                                           ClientAttestation attestation,
                                                           KeycloakSession session) throws VerificationException {
        // Validate required claims
        if (attestationPoP.getIssuer() == null || attestationPoP.getIssuer().trim().isEmpty()) {
            throw new VerificationException("Client Attestation PoP missing required 'iss' claim");
        }

        if (attestationPoP.getAudience() == null || attestationPoP.getAudience().length == 0) {
            throw new VerificationException("Client Attestation PoP missing required 'aud' claim");
        }

        if (attestationPoP.getId() == null || attestationPoP.getId().trim().isEmpty()) {
            throw new VerificationException("Client Attestation PoP missing required 'jti' claim");
        }

        if (attestationPoP.getIssuedAt() == null) {
            throw new VerificationException("Client Attestation PoP missing required 'iat' claim");
        }

        // Validate client_id matches between attestation and PoP
        if (!attestationPoP.getIssuer().equals(attestation.getSubject())) {
            throw new VerificationException("Client Attestation PoP 'iss' claim does not match Client Attestation 'sub' claim");
        }

        // Validate audience matches authorization server
        String expectedAudience = session.getContext().getUri().getBaseUri().toString();
        if (!attestationPoP.hasAudience(expectedAudience)) {
            throw new VerificationException("Client Attestation PoP 'aud' claim does not match authorization server");
        }

        // Validate timing
        if (!attestationPoP.isActive(DEFAULT_ALLOWED_CLOCK_SKEW)) {
            throw new VerificationException("Client Attestation PoP has expired");
        }

        // Validate not-before time if present
        if (attestationPoP.getNotBefore() != null && attestationPoP.getNotBefore() > Time.currentTime() + DEFAULT_ALLOWED_CLOCK_SKEW) {
            throw new VerificationException("Client Attestation PoP is not yet valid");
        }

        // Check for server-provided challenge if present (optional feature)
        validateServerProvidedChallenge(attestationPoP, session);

        // Implement replay protection using jti (reusing DPoP pattern)
        validateJtiReplayProtection(attestationPoP, session);
    }

    private static void validateJtiReplayProtection(ClientAttestationPoP attestationPoP, KeycloakSession session) throws VerificationException {
        SingleUseObjectProvider singleUseCache = session.singleUseObjects();
        String jti = attestationPoP.getId();

        // Calculate lifespan based on iat and current time
        long currentTime = Time.currentTime();
        long iat = attestationPoP.getIssuedAt();
        int lifespan = (int) (DEFAULT_ATTESTATION_LIFETIME - (currentTime - iat));

        if (lifespan <= 0) {
            throw new VerificationException("Client Attestation PoP jti is too old for replay protection");
        }

        // Use jti as the key for replay protection (similar to DPoP pattern)
        if (!singleUseCache.putIfAbsent(jti, lifespan)) {
            throw new VerificationException("Client Attestation PoP jti has already been used");
        }
    }

    /**
     * Validates server-provided challenge if present (optional feature).
     * This should use the use_attestation_challenge error code.
     */
    private static void validateServerProvidedChallenge(ClientAttestationPoP attestationPoP, KeycloakSession session) throws VerificationException {
        String expectedChallenge = session.getAttribute("client-attestation.expected-challenge", String.class);
        if (expectedChallenge != null && !expectedChallenge.trim().isEmpty()) {
            String providedChallenge = attestationPoP.getChallenge();
            if (providedChallenge == null || !expectedChallenge.equals(providedChallenge)) {
                throw new ClientAttestationChallengeException("Client Attestation PoP challenge does not match expected server challenge");
            }
        }
    }

    /**
     * Validates that the Client Attestation is fresh enough.
     * This should use the use_fresh_attestation error code.
     */
    private static void validateAttestationFreshness(ClientAttestation attestation) throws VerificationException {
        // Check if attestation is too old (beyond acceptable freshness window)
        long currentTime = Time.currentTime();
        Long issuedAt = attestation.getIat();
        long maxAge = DEFAULT_ATTESTATION_LIFETIME * 2; // Allow 2x the normal lifetime for freshness

        if (issuedAt != null && (currentTime - issuedAt) > maxAge) {
            throw new ClientAttestationFreshnessException("Client Attestation is not fresh enough");
        }
    }

    /**
     * Verifies the Client Attestation signature against a trusted attester's key.
     * This is the critical security check that ensures the attestation was issued by a trusted attester.
     * <p>
     * According to the OAuth 2.0 Attestation-Based Client Authentication specification:
     * - The 'iss' claim identifies the attester
     * - The attester must be in the list of trusted attesters
     * - The signature must verify with the attester's public key
     */
    private static void verifyAttesterSignature(KeycloakSession session, TokenVerifier<ClientAttestation> verifier, String token) throws VerificationException {
        try {
            // Get the issuer (attester) from the JWT payload
            // We need to decode the payload without signature verification first to get the issuer
            String issuer = null;
            try {
                // Parse the JWT to get the issuer claim
                String[] parts = token.split("\\.");
                if (parts.length != 3) {
                    throw new VerificationException("Invalid JWT format");
                }

                // Decode the payload (base64url decode)
                String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
                ObjectMapper mapper = new ObjectMapper();
                JsonNode payloadJson = mapper.readTree(payload);
                issuer = payloadJson.get("iss").asText();
            } catch (Exception e) {
                throw new VerificationException("Cannot determine attester issuer for signature verification: " + e.getMessage());
            }

            if (issuer == null || issuer.trim().isEmpty()) {
                throw new VerificationException("Client Attestation missing attester issuer");
            }

            // Check if the attester is trusted using Keycloak's configuration system
            if (!isTrustedAttester(session, issuer)) {
                throw new VerificationException("Attester '" + issuer + "' is not in the list of trusted attesters");
            }

            // Resolve the attester's public key using Keycloak's PublicKeyStorageProvider
            SignatureVerifierContext attesterVerifier = resolveAttesterKey(session, issuer, verifier.getHeader().getKeyId(), verifier);
            if (attesterVerifier == null) {
                throw new VerificationException("Cannot resolve public key for trusted attester: " + issuer);
            }

            // Set up the signature verifier with the attester's key
            verifier.verifierContext(attesterVerifier);

        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationException("Failed to verify attester signature: " + e.getMessage(), e);
        }
    }

    /**
     * Validates that client_id parameter matches attestation claims
     */
    private static void validateClientIdMatch(HttpRequest request, ClientAttestation attestation, ClientAttestationPoP attestationPoP) throws VerificationException {
        String clientIdFromRequest = request.getDecodedFormParameters().getFirst("client_id");
        if (clientIdFromRequest != null) {
            String clientIdFromAttestation = attestation.getSubject();
            String clientIdFromAttestationPoP = attestationPoP.getIssuer();

            if (!clientIdFromRequest.equals(clientIdFromAttestation) ||
                    !clientIdFromRequest.equals(clientIdFromAttestationPoP)) {
                throw new VerificationException("client_id parameter does not match attestation claims");
            }
        }
    }

    /**
     * Checks if the given issuer is in the list of trusted attesters.
     * Uses Keycloak's standard configuration patterns similar to OIDCIdentityProvider.
     * <p>
     * Configuration follows Keycloak's standard pattern:
     * 1. Realm-specific configuration (realm attributes)
     * 2. Global configuration (system properties)
     */
    private static boolean isTrustedAttester(KeycloakSession session, String issuer) {
        // Check realm-specific configuration first (following OIDCIdentityProvider pattern)
        String trustedAttesters = session.getContext().getRealm().getAttribute("client-attestation.trusted-attesters");
        if (trustedAttesters != null && !trustedAttesters.trim().isEmpty()) {
            return isAttesterInList(issuer, trustedAttesters);
        }

        // Check global configuration via system properties (following Keycloak patterns)
        String globalTrustedAttesters = System.getProperty("keycloak.client-attestation.trusted-attesters");
        if (globalTrustedAttesters != null && !globalTrustedAttesters.trim().isEmpty()) {
            return isAttesterInList(issuer, globalTrustedAttesters);
        }

        // Default: no trusted attesters configured
        return false;
    }

    /**
     * Helper method to check if an attester is in a comma-separated list of trusted attesters.
     * Follows the same pattern as OIDCIdentityProvider for trusted issuers.
     */
    private static boolean isAttesterInList(String issuer, String trustedAttestersList) {
        if (trustedAttestersList == null || trustedAttestersList.trim().isEmpty()) {
            return false;
        }

        String[] trustedAttesters = trustedAttestersList.split(",");
        for (String trustedAttester : trustedAttesters) {
            if (issuer != null && issuer.equals(trustedAttester.trim())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Resolves the public key for the given attester using Keycloak's PublicKeyStorageProvider.
     * This leverages Keycloak's existing JWKS caching and key resolution infrastructure.
     */
    private static SignatureVerifierContext resolveAttesterKey(KeycloakSession session, String issuer, String keyId, TokenVerifier<ClientAttestation> verifier) throws VerificationException {
        try {
            // Use Keycloak's PublicKeyStorageProvider for caching and key resolution
            PublicKeyStorageProvider keyStorage = session.getProvider(PublicKeyStorageProvider.class);

            // Create a cache key for this attester following Keycloak's pattern
            String modelKey = "client-attestation-attester-" + issuer.hashCode();

            // Create a key loader that fetches JWKS from the attester
            AttesterJWKSLoader keyLoader = new AttesterJWKSLoader(session, issuer);

            // Get the key from storage (with caching) - use algorithm from JWT header
            String algorithm = null;
            KeyWrapper keyWrapper = keyStorage.getPublicKey(modelKey, keyId, algorithm, keyLoader);

            if (keyWrapper == null || keyWrapper.getPublicKey() == null) {
                throw new VerificationException("Cannot resolve public key for attester: " + issuer);
            }

            // Create SignatureVerifierContext using the resolved key
            // Use the algorithm from the JWT header
            String jwtAlgorithm = verifier.getHeader().getRawAlgorithm();
            if (keyWrapper.getAlgorithm() == null) {
                keyWrapper.setAlgorithm(jwtAlgorithm);
            } else if (!keyWrapper.getAlgorithm().equals(jwtAlgorithm)) {
                throw new VerificationException("Key algorithm does not match JWT algorithm: key=" + keyWrapper.getAlgorithm() + ", jwt=" + jwtAlgorithm);
            }

            SignatureVerifierContext verifierContext = session.getProvider(SignatureProvider.class, keyWrapper.getAlgorithm()).verifier(keyWrapper);

            return verifierContext;

        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationException("Failed to resolve attester key: " + e.getMessage(), e);
        }
    }

    /**
     * Key loader for attester JWKS that implements Keycloak's PublicKeyLoader interface.
     * This integrates with Keycloak's existing JWKS fetching and caching infrastructure.
     */
    private static class AttesterJWKSLoader implements PublicKeyLoader {
        private final KeycloakSession session;
        private final String issuer;

        public AttesterJWKSLoader(KeycloakSession session, String issuer) {
            this.session = session;
            this.issuer = issuer;
        }

        @Override
        public PublicKeysWrapper loadKeys() throws Exception {
            // Construct JWKS endpoint URL
            String jwksUrl = issuer.endsWith("/") ? issuer + ".well-known/jwks.json" : issuer + "/.well-known/jwks.json";

            // Use Keycloak's existing JWKS HTTP utilities
            JSONWebKeySet jwks = JWKSHttpUtils.sendJwksRequest(session, jwksUrl);

            // Convert JSONWebKeySet to List<KeyWrapper>
            List<KeyWrapper> keyWrappers = new ArrayList<>();
            for (JWK jwk : jwks.getKeys()) {
                if (JWK.Use.SIG.asString().equals(jwk.getPublicKeyUse())) {
                    KeyWrapper keyWrapper = JWKSUtils.getKeyWrapper(jwk);
                    if (keyWrapper != null) {
                        keyWrappers.add(keyWrapper);
                    }
                }
            }

            return new PublicKeysWrapper(keyWrappers);
        }
    }


    private static List<String> getClientAttestationSupportedAlgorithms(KeycloakSession session) {
        return session.getKeycloakSessionFactory().getProviderFactoriesStream(SignatureProvider.class)
                .map(providerFactory -> providerFactory.getId())
                .filter(algorithm -> {
                    SignatureProvider provider = session.getProvider(SignatureProvider.class, algorithm);
                    return provider != null && provider.isAsymmetricAlgorithm();
                })
                .collect(Collectors.toList());
    }

    /**
     * Exception for Client Attestation challenge validation errors.
     * Maps to the use_attestation_challenge error code from the spec.
     */
    public static class ClientAttestationChallengeException extends VerificationException {
        public ClientAttestationChallengeException(String message) {
            super(message);
        }
    }

    /**
     * Exception for Client Attestation freshness validation errors.
     * Maps to the use_fresh_attestation error code from the spec.
     */
    public static class ClientAttestationFreshnessException extends VerificationException {
        public ClientAttestationFreshnessException(String message) {
            super(message);
        }
    }

    public static class Validator {

        private String attestation;
        private String attestationPoP;
        private ClientAttestation clientAttestation;

        private final KeycloakSession session;

        public Validator(KeycloakSession session) {
            this.session = session;
        }

        public Validator request(HttpRequest request) {
            this.attestation = request.getHttpHeaders().getHeaderString(OAuth2Constants.CLIENT_ATTESTATION_HTTP_HEADER);
            this.attestationPoP = request.getHttpHeaders().getHeaderString(OAuth2Constants.CLIENT_ATTESTATION_POP_HTTP_HEADER);
            return this;
        }

        public Validator attestation(ClientAttestation attestation) {
            this.clientAttestation = attestation;
            return this;
        }

        public ClientAttestation validateAttestation() throws VerificationException {
            return validateClientAttestation(session, attestation);
        }

        public ClientAttestationPoP validateAttestationPoP() throws VerificationException {
            return validateClientAttestationPoP(session, attestationPoP, clientAttestation);
        }
    }
}
