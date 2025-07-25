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
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProvider;
import org.keycloak.protocol.oid4vc.issuance.VCIssuanceContext;
import org.keycloak.protocol.oid4vc.issuance.VCIssuerException;
import org.keycloak.protocol.oid4vc.model.ISO18045ResistanceLevel;
import org.keycloak.protocol.oid4vc.model.KeyAttestationJwtBody;
import org.keycloak.protocol.oid4vc.model.KeyAttestationsRequired;
import org.keycloak.protocol.oid4vc.model.SupportedProofTypeData;
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
import java.util.stream.Collectors;

import static org.keycloak.services.clientpolicy.executor.FapiConstant.ALLOWED_ALGORITHMS;

/**
 * Utility for validating attestation JWTs as per OID4VCI spec.
 *
 * @author <a href="mailto:Rodrick.Awambeng@adorsys.com">Rodrick Awambeng</a>
 */
public class AttestationValidatorUtil {

    public static final String ATTESTATION_JWT_TYP = "keyattestation+jwt";
    private static final String CACERTS_PATH = System.getProperty("javax.net.ssl.trustStore",
            System.getProperty("java.home") + "/lib/security/cacerts");
    private static final char[] DEFAULT_TRUSTSTORE_PASSWORD = System.getProperty(
            "javax.net.ssl.trustStorePassword", "changeit").toCharArray();

    public static KeyAttestationJwtBody validateAttestationJwt(
            String attestationJwt,
            KeycloakSession keycloakSession,
            VCIssuanceContext vcIssuanceContext,
            AttestationKeyResolver keyResolver) throws IOException, JWSInputException,
            VerificationException, GeneralSecurityException {

        if (attestationJwt == null || attestationJwt.isEmpty()) {
            throw new VCIssuerException("Attestation JWT is missing");
        }

        JWSInput jwsInput = new JWSInput(attestationJwt);
        JWSHeader header = jwsInput.getHeader();
        validateJwsHeader(header);

        // Parse payload into proper object
        KeyAttestationJwtBody attestationBody = JsonSerialization.readValue(
                jwsInput.getContent(), KeyAttestationJwtBody.class);

        // Signature verification remains the same
        Map<String, Object> rawHeader = JsonSerialization.mapper.readValue(
                jwsInput.getEncodedHeader(), new TypeReference<>() {});

        SignatureVerifierContext verifier;
        if (header.getX5c() != null && !header.getX5c().isEmpty()) {
            verifier = verifierFromX5CChain(header.getX5c(), header.getAlgorithm().name(), keycloakSession);
        } else if (header.getKeyId() != null) {
            JWK resolvedJwk = keyResolver.resolveKey(header.getKeyId(), rawHeader,
                    JsonSerialization.mapper.convertValue(attestationBody, Map.class));
            verifier = verifierFromResolvedJWK(resolvedJwk, header.getAlgorithm().name(), keycloakSession);
        } else {
            throw new VCIssuerException("Neither x5c nor kid present in attestation JWT header");
        }

        if (!verifier.verify(jwsInput.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8),
                jwsInput.getSignature())) {
            throw new VCIssuerException("Could not verify signature of attestation JWT");
        }

        validateAttestationPayload(keycloakSession, vcIssuanceContext, attestationBody);
        return attestationBody;
    }

    private static void validateAttestationPayload(
            KeycloakSession keycloakSession,
            VCIssuanceContext vcIssuanceContext,
            KeyAttestationJwtBody attestationBody) throws VCIssuerException, VerificationException {

        if (attestationBody.getIat() == null) {
            throw new VCIssuerException("Missing 'iat' claim in attestation");
        }

        if (attestationBody.getNonce() == null) {
            throw new VCIssuerException("Missing 'nonce' in attestation");
        }

        CNonceHandler cNonceHandler = keycloakSession.getProvider(CNonceHandler.class);
        if (cNonceHandler == null) {
            throw new VCIssuerException("No CNonceHandler available");
        }

        // Get resistance level requirements from configuration
        KeyAttestationsRequired attestationRequirements = getAttestationRequirements(vcIssuanceContext);

        // Validate key_storage if present in attestation and required by config
        if (attestationBody.getKeyStorage() != null) {
            validateResistanceLevel(
                    attestationBody.getKeyStorage(),
                    attestationRequirements != null ? attestationRequirements.getKeyStorage() : null,
                    "key_storage");
        }

        // Validate user_authentication if present in attestation and required by config
        if (attestationBody.getUserAuthentication() != null) {
            validateResistanceLevel(
                    attestationBody.getUserAuthentication(),
                    attestationRequirements != null ? attestationRequirements.getUserAuthentication() : null,
                    "user_authentication");
        }

        cNonceHandler.verifyCNonce(
                attestationBody.getNonce(),
                List.of(OID4VCIssuerWellKnownProvider.getCredentialsEndpoint(
                        keycloakSession.getContext())),
                Map.of(JwtCNonceHandler.SOURCE_ENDPOINT,
                        OID4VCIssuerWellKnownProvider.getNonceEndpoint(
                                keycloakSession.getContext()))
        );

        // Store attested keys in context for later use
        if (attestationBody.getAttestedKeys() != null) {
            vcIssuanceContext.setAttestedKeys(attestationBody.getAttestedKeys());
        }
    }

    private static KeyAttestationsRequired getAttestationRequirements(VCIssuanceContext vcIssuanceContext) {
        if (vcIssuanceContext.getCredentialConfig() == null ||
                vcIssuanceContext.getCredentialConfig().getProofTypesSupported() == null ||
                vcIssuanceContext.getCredentialConfig().getProofTypesSupported().getSupportedProofTypes() == null) {
            return null;
        }

        SupportedProofTypeData proofTypeData = vcIssuanceContext.getCredentialConfig()
                .getProofTypesSupported()
                .getSupportedProofTypes()
                .get("jwt");

        return proofTypeData != null ? proofTypeData.getKeyAttestationsRequired() : null;
    }

    private static void validateResistanceLevel(
            List<String> actualLevels,
            List<ISO18045ResistanceLevel> requiredLevels,
            String levelType) throws VCIssuerException {

        if (requiredLevels == null || requiredLevels.isEmpty()) {
            for (String level : actualLevels) {
                try {
                    ISO18045ResistanceLevel.fromValue(level);
                } catch (Exception e) {
                    throw new VCIssuerException("Invalid " + levelType + " level: " + level);
                }
            }
            return;
        }

        // Convert required levels to string values for comparison
        Set<String> requiredLevelValues = requiredLevels.stream()
                .map(ISO18045ResistanceLevel::getValue)
                .collect(Collectors.toSet());

        // Check each actual level against requirements
        for (String level : actualLevels) {
            try {
                ISO18045ResistanceLevel levelEnum = ISO18045ResistanceLevel.fromValue(level);
                if (!requiredLevelValues.contains(levelEnum.getValue())) {
                    throw new VCIssuerException(
                            levelType + " level '" + level + "' is not accepted by credential issuer. " +
                                    "Allowed values: " + requiredLevelValues);
                }
            } catch (IllegalArgumentException e) {
                throw new VCIssuerException("Invalid " + levelType + " level: " + level);
            }
        }
    }

    private static void validateJwsHeader(JWSHeader header) {
        String alg = Optional.ofNullable(header.getAlgorithm())
                .map(Algorithm::name)
                .orElseThrow(() -> new VCIssuerException("Missing algorithm in JWS header"));

        if ("none".equalsIgnoreCase(alg)) {
            throw new VCIssuerException("'none' algorithm is not allowed");
        }

        if (!ALLOWED_ALGORITHMS.contains(alg)) {
            throw new VCIssuerException("Unsupported algorithm: " + alg +
                    ". Allowed algorithms: " + ALLOWED_ALGORITHMS);
        }

        if (!ATTESTATION_JWT_TYP.equals(header.getType())) {
            throw new VCIssuerException("Invalid JWT typ: expected " + ATTESTATION_JWT_TYP);
        }
    }

    private static SignatureVerifierContext verifierFromX5CChain(
            List<String> x5cList,
            String alg,
            KeycloakSession keycloakSession
    ) throws GeneralSecurityException, IOException, VerificationException {

        if (x5cList.isEmpty()) {
            throw new VCIssuerException("Empty x5c header in attestation JWT");
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
        Set<TrustAnchor> anchors = loadTrustAnchorsFromDefaultTrustStore();

        PKIXParameters params = new PKIXParameters(anchors);
        params.setRevocationEnabled(false);

        CertPathValidator.getInstance("PKIX").validate(certPath, params);

        PublicKey publicKey = certChain.get(0).getPublicKey();
        JWK certJwk = convertPublicKeyToJWK(publicKey, alg, certChain);

        return verifierFromResolvedJWK(certJwk, alg, keycloakSession);
    }

    private static SignatureVerifierContext verifierFromResolvedJWK(
            JWK jwk,
            String alg,
            KeycloakSession session
    ) throws VerificationException {

        SignatureProvider provider = session.getProvider(SignatureProvider.class, alg);
        KeyWrapper wrapper = new KeyWrapper();
        wrapper.setType(jwk.getKeyType());
        wrapper.setAlgorithm(alg);
        wrapper.setUse(KeyUse.SIG);

        if (jwk.getOtherClaims().get("crv") != null) {
            wrapper.setCurve((String) jwk.getOtherClaims().get("crv"));
        }

        wrapper.setPublicKey(JWKParser.create(jwk).toPublicKey());
        return provider.verifier(wrapper);
    }

    private static JWK convertPublicKeyToJWK(
            PublicKey key,
            String alg,
            List<X509Certificate> certChain
    ) {
        if (key instanceof RSAPublicKey rsa) {
            return JWKBuilder.create().algorithm(alg).rsa(rsa, certChain);
        } else if (key instanceof ECPublicKey ec) {
            return JWKBuilder.create().algorithm(alg).ec(ec, certChain, null);
        } else {
            throw new VCIssuerException("Unsupported public key type in certificate: " + key.getClass().getName());
        }
    }

    private static Set<TrustAnchor> loadTrustAnchorsFromDefaultTrustStore()
            throws GeneralSecurityException, IOException {

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

        return anchors;
    }
}
