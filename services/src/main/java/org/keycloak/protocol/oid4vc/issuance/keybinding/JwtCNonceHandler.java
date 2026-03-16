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
 *
 */

package org.keycloak.protocol.oid4vc.issuance.keybinding;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Random;

import jakarta.annotation.Nullable;

import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Time;
import org.keycloak.constants.OID4VCIConstants;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProvider;
import org.keycloak.protocol.oid4vc.model.JwtCNonce;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.saml.RandomSecret;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Pascal Knüppel
 */
public class JwtCNonceHandler implements CNonceHandler {

    public static final String SOURCE_ENDPOINT = OID4VCIConstants.SOURCE_ENDPOINT;

    public static final int NONCE_DEFAULT_LENGTH = 50;

    public static final int NONCE_LENGTH_RANDOM_OFFSET = 15;

    private static final Logger logger = LoggerFactory.getLogger(JwtCNonceHandler.class);

    private final KeycloakSession keycloakSession;

    private final KeyWrapper signingKey;

    public JwtCNonceHandler(KeycloakSession keycloakSession) {
        this.keycloakSession = keycloakSession;
        this.signingKey = selectSigningKey(keycloakSession.getContext().getRealm());
    }

    @Override
    public String buildCNonce(List<String> audiences, Map<String, Object> additionalDetails) {
        RealmModel realm = keycloakSession.getContext().getRealm();
        final String issuer = OID4VCIssuerWellKnownProvider.getIssuer(keycloakSession.getContext());
        // TODO discussion about the attribute name to use
        final Integer nonceLifetimeSeconds = realm.getAttribute(OID4VCIConstants.C_NONCE_LIFETIME_IN_SECONDS, 60);
        audiences = Optional.ofNullable(audiences).orElseGet(Collections::emptyList);
        final long nowSeconds = Time.currentTime();
        final long expiresAt = nowSeconds + nonceLifetimeSeconds;
        final int nonceLength = NONCE_DEFAULT_LENGTH + new Random().nextInt(NONCE_LENGTH_RANDOM_OFFSET);
        // this generated value itself is basically just a salt-value for the generated token, which itself is the nonce.
        final String strongSalt = Base64.getEncoder().encodeToString(RandomSecret.createRandomSecret(nonceLength));

        JsonWebToken jwtCNonce = new JwtCNonce().salt(strongSalt)
                                                .issuer(issuer)
                                                .audience(audiences.toArray(String[]::new))
                                                .exp(expiresAt);
        Optional.ofNullable(additionalDetails).ifPresent(map -> {
            map.forEach(jwtCNonce::setOtherClaims);
        });

        SignatureProvider signatureProvider = keycloakSession.getProvider(SignatureProvider.class,
                                                                          signingKey.getAlgorithm());
        SignatureSignerContext signatureSignerContext = signatureProvider.signer(signingKey);
        return new JWSBuilder().jsonContent(jwtCNonce).sign(signatureSignerContext);
    }

    @Override
    public void verifyCNonce(String cNonce, List<String> audiences, @Nullable Map<String, Object> additionalDetails)
            throws VerificationException {
        if (cNonce == null) {
            throw new VerificationException("c_nonce is required");
        }

        // Reject nonces that have already been consumed (replay protection)
        if (keycloakSession.singleUseObjects().contains(cNonce)) {
            throw new VerificationException("c_nonce has already been used");
        }

        verifyCNonceToken(cNonce, audiences, additionalDetails);
    }

    /**
     * Marks a c_nonce as consumed so that subsequent replay attempts are rejected.
     * <p>
     * The TTL for the single-use record is derived from the {@code exp} claim inside the
     * JWT c_nonce itself, so the record naturally expires when the nonce would have expired
     * anyway. This avoids using an arbitrary hard-coded TTL.
     * </p>
     *
     * @param cNonce the nonce to consume
     * @throws VerificationException if the nonce was already consumed or cannot be parsed
     */
    public void consumeCNonce(String cNonce) throws VerificationException {
        if (cNonce == null) {
            throw new VerificationException("c_nonce is required");
        }

        // Derive TTL from the exp claim in the JWT c_nonce
        int ttlSeconds = getExpirationTtl(cNonce);

        if (!keycloakSession.singleUseObjects().putIfAbsent(cNonce, ttlSeconds)) {
            throw new VerificationException("c_nonce has already been used");
        }
    }

    /**
     * Extracts the remaining TTL (in seconds) from the {@code exp} claim of a JWT c_nonce.
     * Falls back to the configured nonce lifetime if the token cannot be parsed or has no exp.
     */
    private int getExpirationTtl(String cNonce) {
        try {
            TokenVerifier<JsonWebToken> tokenVerifier = TokenVerifier.create(cNonce, JsonWebToken.class);
            JsonWebToken token = tokenVerifier.getToken();
            Long exp = token.getExp();
            if (exp != null) {
                long remaining = exp - Time.currentTime();
                // Use at least 60s to guard against clock skew; cap at a reasonable upper bound
                return (int) Math.max(60, remaining);
            }
        } catch (VerificationException e) {
            logger.debug("Could not parse c_nonce JWT to extract exp for TTL; using default", e);
        }
        // Fallback: use the configured nonce lifetime
        RealmModel realm = keycloakSession.getContext().getRealm();
        return realm.getAttribute(OID4VCIConstants.C_NONCE_LIFETIME_IN_SECONDS, 60);
    }

    /**
     * Verifies the JWT c_nonce token (signature, issuer, audience, salt, expiration, additional claims).
     * This is a pure verification with no side effects on replay state.
     */
    private void verifyCNonceToken(String cNonce, List<String> audiences, @Nullable Map<String, Object> additionalDetails)
            throws VerificationException {
        TokenVerifier<JsonWebToken> verifier = TokenVerifier.create(cNonce, JsonWebToken.class);
        KeycloakContext keycloakContext = keycloakSession.getContext();
        List<TokenVerifier.Predicate<JsonWebToken>> verifiers = //
                new ArrayList<>(List.of(jwt -> {
                                            String expectedIssuer = OID4VCIssuerWellKnownProvider.getIssuer(keycloakContext);
                                            if (!expectedIssuer.equals(jwt.getIssuer())) {
                                                String message = String.format(
                                                    "c_nonce issuer did not match: %s(expected) != %s(actual)",
                                                    expectedIssuer, jwt.getIssuer());
                                                throw new VerificationException(message);
                                            }
                                            return true;
                                        }, jwt -> {
                                            List<String> actualValue = Optional.ofNullable(jwt.getAudience())
                                                                               .map(Arrays::asList)
                                                                               .orElse(List.of());
                                            return checkAttributeEquality("aud", audiences, actualValue);
                                        },jwt -> {
                                            String salt = Optional.ofNullable(jwt.getOtherClaims())
                                                                   .map(m -> String.valueOf(m.get("salt")))
                                                                   .orElse(null);
                                            final int saltLength = Optional.ofNullable(salt).map(String::length)
                                                                            .orElse(0);
                                            if (saltLength < NONCE_DEFAULT_LENGTH){
                                                String message = String.format(
                                                    "c_nonce-salt is not of expected length: %s(actual) < %s(expected)",
                                                    saltLength, NONCE_DEFAULT_LENGTH);
                                                throw new VerificationException(message);
                                            }
                                            return true;
                                        },
                                        jwt -> {
                                            Long exp = jwt.getExp();
                                            if (exp == null) {
                                                throw new VerificationException("c_nonce has no expiration time");
                                            }
                                            long now = Time.currentTime();
                                            if (exp < now) {
                                                String message = String.format(
                                                        "c_nonce not valid: %s(exp) < %s(now)",
                                                        exp,
                                                        now);
                                                throw new VerificationException(message);
                                            }
                                            return true;
                                        }));
        Optional.ofNullable(additionalDetails).ifPresent(map -> {
            map.forEach((key, object) -> {
                verifiers.add(jwt -> {
                    Object actualValue = Optional.ofNullable(jwt.getOtherClaims())
                                                 .map(claimMap -> claimMap.get(key))
                                                 .orElse(null);
                    return checkAttributeEquality(key, object, actualValue);
                });
            });
        });
        verifier.withChecks(verifiers.toArray(new TokenVerifier.Predicate[0]));
        SignatureVerifierContext signatureVerifier = keycloakSession.getProvider(SignatureProvider.class,
                                                                                 signingKey.getAlgorithm())
                                                                    .verifier(signingKey);
        verifier.verifierContext(signatureVerifier);
        verifier.verify(); // throws a VerificationException on failure
    }

    protected boolean checkAttributeEquality(String key, Object object, Object actualValue) throws VerificationException {
        boolean isEqual = Objects.equals(object, actualValue);
        if (!isEqual) {
            String message = String.format(
                    "c_nonce: expected '%s' to be equal to '%s' but actual value was '%s'",
                    key,
                    object,
                    actualValue);
            throw new VerificationException(message);
        }
        return isEqual;
    }

    protected KeyWrapper selectSigningKey(RealmModel realm) {
        KeyWrapper signingKey;
        try {
            signingKey = keycloakSession.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.ES256);
        } catch (RuntimeException ex) {
            logger.debug("Failed to find active ES256 signing key for realm {}. Falling back to RSA...",
                         realm.getName());
            logger.debug(ex.getMessage(), ex);
            // use RSA only as fallback since the preferred algorithm by OpenID4VC is elliptic curve
            signingKey = keycloakSession.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
        }
        return signingKey;
    }
}
