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

package org.keycloak.protocol.oid4vc.issuance.keybinding;

import com.fasterxml.jackson.core.type.TypeReference;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProvider;
import org.keycloak.protocol.oid4vc.issuance.VCIssuanceContext;
import org.keycloak.protocol.oid4vc.issuance.VCIssuerException;
import org.keycloak.protocol.oid4vc.model.ISO18045ResistanceLevel;
import org.keycloak.util.JsonSerialization;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Utility for validating attestation JWTs as per OID4VCI spec.
 *
 * @author <a href="mailto:Rodrick.Awambeng@adorsys.com">Rodrick Awambeng</a>
 */
public class AttestationValidatorUtil {

    private static final String ATTESTATION_JWT_TYP = "keyattestation+jwt";
    private static final String CACERTS_PATH =
            System.getProperty("java.home") + "/lib/security/cacerts";
    private static final char[] DEFAULT_TRUSTSTORE_PASSWORD = "changeit".toCharArray();

    /**
     * Validates the attestation JWT and returns the list of attested JWKs.
     * Throws VCIssuerException if validation fails.
     */
    public static List<JWK> validateAttestationJwt(
            String attestationJwt,
            KeycloakSession keycloakSession,
            VCIssuanceContext vcIssuanceContext
    ) throws IOException, JWSInputException, VerificationException, GeneralSecurityException {
        if (attestationJwt == null || attestationJwt.isEmpty()) {
            throw new VCIssuerException("Attestation JWT is missing");
        }

        JWSInput jwsInput = new JWSInput(attestationJwt);
        JWSHeader header = jwsInput.getHeader();

        validateJwsHeader(vcIssuanceContext, header);

        SignatureVerifierContext verifier = verifierFromX5CChain(
                header.getX5c(), header.getAlgorithm().name(), keycloakSession
        );

        if (!verifier.verify(
                jwsInput.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8),
                jwsInput.getSignature()
        )) {
            throw new VCIssuerException("Could not verify signature of attestation JWT");
        }

        Map<String, Object> payload = JsonSerialization.mapper.readValue(
                jwsInput.getContent(), new TypeReference<>() {
                }
        );

        validateAttestationPayload(keycloakSession, vcIssuanceContext, payload);

        List<Map<String, Object>> keyMaps =
                (List<Map<String, Object>>) payload.get("attested_keys");

        if (keyMaps == null || keyMaps.isEmpty()) {
            throw new VCIssuerException("No attested_keys found in attestation payload");
        }

        List<JWK> jwks = new ArrayList<>();
        for (Map<String, Object> keyMap : keyMaps) {
            jwks.add(JsonSerialization.mapper.convertValue(keyMap, JWK.class));
        }

        return jwks;
    }

    private static void validateJwsHeader(
            VCIssuanceContext vcIssuanceContext,
            JWSHeader header
    ) {
        String alg = Optional.ofNullable(header.getAlgorithm())
                .map(Enum::name)
                .orElseThrow(() -> new VCIssuerException("Missing algorithm in JWS header"));

        if (!ATTESTATION_JWT_TYP.equals(header.getType())) {
            throw new VCIssuerException("Invalid JWT typ: expected " + ATTESTATION_JWT_TYP);
        }
    }

    private static SignatureVerifierContext verifierFromX5CChain(
            List<String> x5cList,
            String alg,
            KeycloakSession keycloakSession
    ) throws GeneralSecurityException, IOException, VerificationException {
        if (x5cList == null || x5cList.isEmpty()) {
            throw new VCIssuerException("Missing x5c header in attestation JWT");
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certChain = new ArrayList<>();

        for (String certBase64 : x5cList) {
            byte[] certBytes = Base64.getDecoder().decode(certBase64);
            try (InputStream in = new ByteArrayInputStream(certBytes)) {
                certChain.add((X509Certificate) cf.generateCertificate(in));
            }
        }

        CertPath certPath = cf.generateCertPath(certChain);

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream in = new FileInputStream(CACERTS_PATH)) {
            trustStore.load(in, DEFAULT_TRUSTSTORE_PASSWORD);
        }

        Set<TrustAnchor> anchors = new HashSet<>();
        Enumeration<String> aliases = trustStore.aliases();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate cert = trustStore.getCertificate(alias);
            if (cert instanceof X509Certificate x509) {
                anchors.add(new TrustAnchor(x509, null));
            }
        }

        PKIXParameters params = new PKIXParameters(anchors);
        params.setRevocationEnabled(false);

        CertPathValidator.getInstance("PKIX").validate(certPath, params);

        X509Certificate leaf = certChain.get(0);
        PublicKey publicKey = leaf.getPublicKey();
        JWK certJwk;

        if (publicKey instanceof RSAPublicKey rsa) {
            certJwk = JWKBuilder.create()
                    .algorithm(alg)
                    .rsa(rsa, List.of(leaf));
        } else if (publicKey instanceof ECPublicKey ec) {
            certJwk = JWKBuilder.create()
                    .algorithm(alg)
                    .ec(ec, List.of(leaf), null);
        } else {
            throw new VCIssuerException(
                    "Unsupported public key type in certificate chain: " + publicKey.getClass()
            );
        }

        SignatureProvider signatureProvider =
                keycloakSession.getProvider(SignatureProvider.class, alg);

        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setType(certJwk.getKeyType());
        keyWrapper.setAlgorithm(alg);

        if (certJwk.getOtherClaims().get("crv") != null) {
            keyWrapper.setCurve((String) certJwk.getOtherClaims().get("crv"));
        }

        JWKParser parser = JWKParser.create(certJwk);
        keyWrapper.setPublicKey(parser.toPublicKey());
        keyWrapper.setUse(KeyUse.SIG);

        return signatureProvider.verifier(keyWrapper);
    }

    private static void validateAttestationPayload(
            KeycloakSession keycloakSession,
            VCIssuanceContext vcIssuanceContext,
            Map<String, Object> payload
    ) throws VCIssuerException, VerificationException {
        if (!payload.containsKey("iat")) {
            throw new VCIssuerException("Missing 'iat' claim in attestation");
        }

        String nonce = Optional.ofNullable(payload.get("nonce"))
                .map(Object::toString)
                .orElseThrow(() -> new VCIssuerException("Missing 'nonce' in attestation"));

        CNonceHandler cNonceHandler = keycloakSession.getProvider(CNonceHandler.class);

        cNonceHandler.verifyCNonce(
                nonce,
                List.of(OID4VCIssuerWellKnownProvider.getCredentialsEndpoint(
                        keycloakSession.getContext())),
                Map.of(JwtCNonceHandler.SOURCE_ENDPOINT,
                        OID4VCIssuerWellKnownProvider.getNonceEndpoint(
                                keycloakSession.getContext()))
        );

        Object keyStorageClaim = payload.get("key_storage");
        if (keyStorageClaim != null) {
            try {
                ISO18045ResistanceLevel.fromValue(keyStorageClaim.toString());
            } catch (Exception e) {
                throw new VCIssuerException(
                        "Invalid 'key_storage' value in attestation: " + keyStorageClaim, e
                );
            }
        }

        Object userAuthClaim = payload.get("user_authentication");
        if (userAuthClaim != null) {
            try {
                ISO18045ResistanceLevel.fromValue(userAuthClaim.toString());
            } catch (Exception e) {
                throw new VCIssuerException(
                        "Invalid 'user_authentication' value in attestation: " + userAuthClaim, e
                );
            }
        }
    }
}
