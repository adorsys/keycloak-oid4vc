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

package org.keycloak.testsuite.oid4vc.issuance.signing;

import org.jboss.logging.Logger;
import org.junit.Test;
import org.keycloak.constants.Oid4VciConstants;
import org.keycloak.crypto.ECDSASignatureSignerContext;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProvider;
import org.keycloak.protocol.oid4vc.issuance.VCIssuanceContext;
import org.keycloak.protocol.oid4vc.issuance.VCIssuerException;
import org.keycloak.protocol.oid4vc.issuance.keybinding.AttestationKeyResolver;
import org.keycloak.protocol.oid4vc.issuance.keybinding.AttestationProofValidator;
import org.keycloak.protocol.oid4vc.issuance.keybinding.AttestationProofValidatorFactory;
import org.keycloak.protocol.oid4vc.issuance.keybinding.AttestationValidatorUtil;
import org.keycloak.protocol.oid4vc.issuance.keybinding.CNonceHandler;
import org.keycloak.protocol.oid4vc.issuance.keybinding.JwtCNonceHandler;
import org.keycloak.protocol.oid4vc.issuance.keybinding.JwtProofValidator;
import org.keycloak.protocol.oid4vc.issuance.keybinding.ProofValidator;
import org.keycloak.protocol.oid4vc.issuance.keybinding.StaticAttestationKeyResolver;
import org.keycloak.protocol.oid4vc.model.AttestationProof;
import org.keycloak.protocol.oid4vc.model.ISO18045ResistanceLevel;
import org.keycloak.protocol.oid4vc.model.JwtProof;
import org.keycloak.protocol.oid4vc.model.KeyAttestationJwtBody;
import org.keycloak.truststore.TruststoreProvider;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.apache.commons.lang.exception.ExceptionUtils.getRootCauseMessage;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * @author Bertrand Ogen
 *
 * Test class for verifying Key Attestation
 */

public class OID4VCKeyAttestationTest extends OID4VCIssuerEndpointTest {

    private static final Logger LOGGER = Logger.getLogger(OID4VCKeyAttestationTest.class);

    @Test
    public void testValidAttestationProof() {
        testingClient.server(TEST_REALM_NAME).run(session -> {
            try {
                runValidAttestationProofTest(session);
            } catch (Exception e) {
                e.printStackTrace();
                fail("Test should not throw exception: " + e.getMessage() +
                        "\nRoot cause: " + getRootCauseMessage(e));
            }
        });
    }

    @Test
    public void testInvalidAttestationProof() {
        testingClient.server(TEST_REALM_NAME).run(OID4VCKeyAttestationTest::runInvalidAttestationProofTest);
    }

    @Test
    public void testValidJwtProofWithKeyAttestation() {
        testingClient.server(TEST_REALM_NAME).run(OID4VCKeyAttestationTest::runValidJwtProofWithKeyAttestationTest);
    }

    @Test
    public void testInvalidJwtProofWithKeyAttestation() {
        testingClient.server(TEST_REALM_NAME).run(session -> {
            try {
                runInvalidJwtProofWithKeyAttestationTest(session);
                fail("Expected VCIssuerException to be thrown");
            } catch (VCIssuerException e) {
                assertTrue(e.getMessage().contains("Could not validate JWT proof"));
            }
        });
    }

    @Test
    public void testAttestationProofType() {
        testingClient.server(TEST_REALM_NAME).run(session -> {
            AttestationProofValidatorFactory factory = new AttestationProofValidatorFactory();
            ProofValidator validator = factory.create(session);
            assertEquals("The proof type should be 'attestation'.", "attestation", validator.getProofType());
        });
    }

    @Test
    public void testInvalidAttestationSignature() {
        testingClient.server(TEST_REALM_NAME).run(OID4VCKeyAttestationTest::runInvalidAttestationSignatureTest);
    }

    @Test
    public void testMissingRequiredAttestationClaims() {
        testingClient.server(TEST_REALM_NAME).run(OID4VCKeyAttestationTest::runMissingRequiredAttestationClaimsTest);
    }

    @Test
    public void testAttestationWithMultipleAttestedKeys() {
        testingClient.server(TEST_REALM_NAME).run(OID4VCKeyAttestationTest::runAttestationWithMultipleAttestedKeys);
    }

    @Test
    public void testAttestationWithX5cCertificateChain() {
        testingClient.server(TEST_REALM_NAME).run(OID4VCKeyAttestationTest::runAttestationWithX5cCertificateChain);
    }
    @Test
    public void testAttestationWithInvalidResistanceLevels() {
        testingClient.server(TEST_REALM_NAME).run(OID4VCKeyAttestationTest::runAttestationWithInvalidResistanceLevels);
    }

    @Test
    public void testAttestationWithExpiredCNonce() {
        testingClient.server(TEST_REALM_NAME).run(OID4VCKeyAttestationTest::runAttestationWithExpiredCNonce);
    }

    @Test
    public void testAttestationWithMissingAttestedKeys() {
        testingClient.server(TEST_REALM_NAME).run(OID4VCKeyAttestationTest::runAttestationWithMissingAttestedKeys);
    }

    @Test
    public void testAttestationWithInvalidKeyType() {
        testingClient.server(TEST_REALM_NAME).run(OID4VCKeyAttestationTest::runAttestationWithInvalidKeyType);
    }

    private static void runValidAttestationProofTest(KeycloakSession session) throws IOException {
        try {
            KeyWrapper attestationKey = getECKey("attestationKey");
            KeyWrapper proofKey = getECKey("proofKey");
            JWK proofJwk = JWKBuilder.create().ec(proofKey.getPublicKey());
            proofJwk.setKeyId(proofKey.getKid());

            // Get CNonce from the handler to ensure it's properly registered
            CNonceHandler cNonceHandler = session.getProvider(CNonceHandler.class);
            String cNonce = cNonceHandler.buildCNonce(
                    List.of(OID4VCIssuerWellKnownProvider.getCredentialsEndpoint(session.getContext())),
                    Map.of(JwtCNonceHandler.SOURCE_ENDPOINT,
                            OID4VCIssuerWellKnownProvider.getNonceEndpoint(session.getContext()))
            );

            // Create payload using proper KeyAttestationJwtBody class
            KeyAttestationJwtBody payload = new KeyAttestationJwtBody();
            payload.setIat((long) TIME_PROVIDER.currentTimeSeconds());
            payload.setNonce(cNonce);
            payload.setAttestedKeys(proofJwk);
            payload.setKeyStorage(List.of(ISO18045ResistanceLevel.HIGH.getValue()));
            payload.setUserAuthentication(List.of(ISO18045ResistanceLevel.HIGH.getValue()));

            String attestationJwt = new JWSBuilder()
                    .type(AttestationValidatorUtil.ATTESTATION_JWT_TYP)
                    .kid(attestationKey.getKid())
                    .jsonContent(payload)
                    .sign(new ECDSASignatureSignerContext(attestationKey));

            VCIssuanceContext vcIssuanceContext = createVCIssuanceContext(session);
            vcIssuanceContext.getCredentialRequest().setProof(new AttestationProof(attestationJwt));

            AttestationKeyResolver keyResolver = new StaticAttestationKeyResolver(
                    Map.of(attestationKey.getKid(), JWKBuilder.create().ec(attestationKey.getPublicKey()))
            );

            AttestationProofValidator validator = new AttestationProofValidator(session, keyResolver);
            List<JWK> attestedKeys = validator.validateProof(vcIssuanceContext);

            assertNotNull("Attested keys should not be null", attestedKeys);
            assertFalse("Attested keys should not be empty", attestedKeys.isEmpty());
            assertEquals("Should contain exactly one attested key", 1, attestedKeys.size());
            assertEquals("Attested key should match proof key", proofJwk.getKeyId(), attestedKeys.get(0).getKeyId());
        } catch (VCIssuerException e) {
            LOGGER.errorf("Validation failed: %s", e.getMessage(), e);
            fail("Test should not throw VCIssuerException: " + e.getMessage());
        }
    }

    private static void runInvalidAttestationProofTest(KeycloakSession session) {
        KeyWrapper attestationKey = getECKey("attestationKey");
        String invalidAttestationJwt = "invalid.jwt.token";

        VCIssuanceContext vcIssuanceContext = createVCIssuanceContext(session);
        vcIssuanceContext.getCredentialRequest().setProof(new AttestationProof(invalidAttestationJwt));

        AttestationKeyResolver keyResolver = new StaticAttestationKeyResolver(Map.of(attestationKey.getKid(), JWKBuilder.create().ec(attestationKey.getPublicKey())));
        AttestationProofValidator validator = new AttestationProofValidator(session, keyResolver);

        try {
            validator.validateProof(vcIssuanceContext);
            fail("Expected VCIssuerException to be thrown");
        } catch (VCIssuerException e) {
            // Expected exception
        }
    }

    private static void runValidJwtProofWithKeyAttestationTest(KeycloakSession session) {
        try {
            KeyWrapper attestationKey = getECKey("attestationKey");
            KeyWrapper proofKey = getECKey("proofKey");
            JWK proofJwk = JWKBuilder.create().ec(proofKey.getPublicKey());
            String cNonce = getCNonce();

            String attestationJwt = createValidAttestationJwt(session, attestationKey, proofJwk, cNonce);
            String jwtProof = generateJwtProofWithKeyAttestation(session, proofKey, attestationJwt, cNonce);

            VCIssuanceContext vcIssuanceContext = createVCIssuanceContext(session);
            vcIssuanceContext.getCredentialRequest().setProof(new JwtProof(jwtProof));

            AttestationKeyResolver keyResolver = new StaticAttestationKeyResolver(Map.of(attestationKey.getKid(), JWKBuilder.create().ec(attestationKey.getPublicKey())));
            JwtProofValidator validator = new JwtProofValidator(session, keyResolver);

            List<JWK> attestedKeys = validator.validateProof(vcIssuanceContext);
            assertNotNull(attestedKeys);
            assertFalse(attestedKeys.isEmpty());
        } catch (Exception e) {
        }
    }

    private static void runInvalidJwtProofWithKeyAttestationTest(KeycloakSession session) {
        KeyWrapper attestationKey = getECKey("attestationKey");
        String invalidJwtProof = "invalid.jwt.token";

        VCIssuanceContext vcIssuanceContext = createVCIssuanceContext(session);
        vcIssuanceContext.getCredentialRequest().setProof(new JwtProof(invalidJwtProof));

        AttestationKeyResolver keyResolver = new StaticAttestationKeyResolver(Map.of(attestationKey.getKid(), JWKBuilder.create().ec(attestationKey.getPublicKey())));
        JwtProofValidator validator = new JwtProofValidator(session, keyResolver);

        validator.validateProof(vcIssuanceContext);
    }

    private static void runInvalidAttestationSignatureTest(KeycloakSession session) {
        KeyWrapper attestationKey = getECKey("attestationKey");
        KeyWrapper proofKey = getECKey("proofKey");
        JWK proofJwk = JWKBuilder.create().ec(proofKey.getPublicKey());
        String cNonce = getCNonce();

        KeyWrapper unrelatedKey = getECKey("unrelatedKey");
        String invalidAttestationJwt = new JWSBuilder()
                .type(AttestationValidatorUtil.ATTESTATION_JWT_TYP)
                .jwk(JWKBuilder.create().ec(attestationKey.getPublicKey()))
                .jsonContent(createAttestationPayload(proofJwk, cNonce))
                .sign(new ECDSASignatureSignerContext(unrelatedKey));

        VCIssuanceContext vcIssuanceContext = createVCIssuanceContext(session);
        vcIssuanceContext.getCredentialRequest().setProof(new AttestationProof(invalidAttestationJwt));

        AttestationKeyResolver keyResolver = new StaticAttestationKeyResolver(Map.of(attestationKey.getKid(), JWKBuilder.create().ec(attestationKey.getPublicKey())));
        AttestationProofValidator validator = new AttestationProofValidator(session, keyResolver);

        try {
            validator.validateProof(vcIssuanceContext);
            fail("Expected VCIssuerException to be thrown");
        } catch (VCIssuerException e) {
            assertTrue("Expected VCIssuerException to be thrown", true);
        }
    }

    private static void runMissingRequiredAttestationClaimsTest(KeycloakSession session) {
        KeyWrapper attestationKey = getECKey("attestationKey");

        Map<String, Object> incompletePayload = new HashMap<>();
        incompletePayload.put("iat", TIME_PROVIDER.currentTimeSeconds());

        String invalidAttestationJwt = new JWSBuilder()
                .type(AttestationValidatorUtil.ATTESTATION_JWT_TYP)
                .jwk(JWKBuilder.create().ec(attestationKey.getPublicKey()))
                .jsonContent(incompletePayload)
                .sign(new ECDSASignatureSignerContext(attestationKey));

        VCIssuanceContext vcIssuanceContext = createVCIssuanceContext(session);
        vcIssuanceContext.getCredentialRequest().setProof(new AttestationProof(invalidAttestationJwt));

        AttestationKeyResolver keyResolver = new StaticAttestationKeyResolver(Map.of(attestationKey.getKid(), JWKBuilder.create().ec(attestationKey.getPublicKey())));
        AttestationProofValidator validator = new AttestationProofValidator(session, keyResolver);

        try {
            validator.validateProof(vcIssuanceContext);
            fail("Expected VCIssuerException to be thrown");
        } catch (VCIssuerException e) {
            assertTrue("Expected VCIssuerException to be thrown", true);
        }
    }

    private static void runAttestationWithMultipleAttestedKeys(KeycloakSession session) {
        try {
            KeyWrapper attestationKey = getECKey("attestationKey");
            KeyWrapper proofKey1 = getECKey("proofKey1");
            KeyWrapper proofKey2 = getECKey("proofKey2");

            JWK proofJwk1 = JWKBuilder.create().ec(proofKey1.getPublicKey());
            JWK proofJwk2 = JWKBuilder.create().ec(proofKey2.getPublicKey());
            String cNonce = getCNonce();

            KeyAttestationJwtBody payload = new KeyAttestationJwtBody();
            payload.setIat((long) TIME_PROVIDER.currentTimeSeconds());
            payload.setNonce(cNonce);
            payload.setAttestedKeys((JWK) Arrays.asList(proofJwk1, proofJwk2));

            String attestationJwt = new JWSBuilder()
                    .type(AttestationValidatorUtil.ATTESTATION_JWT_TYP)
                    .kid(attestationKey.getKid())
                    .jsonContent(payload)
                    .sign(new ECDSASignatureSignerContext(attestationKey));

            VCIssuanceContext vcIssuanceContext = createVCIssuanceContext(session);
            vcIssuanceContext.getCredentialRequest().setProof(new AttestationProof(attestationJwt));

            AttestationKeyResolver keyResolver = new StaticAttestationKeyResolver(
                    Map.of(attestationKey.getKid(), JWKBuilder.create().ec(attestationKey.getPublicKey()))
            );

            AttestationProofValidator validator = new AttestationProofValidator(session, keyResolver);
            List<JWK> attestedKeys = validator.validateProof(vcIssuanceContext);

            assertEquals(2, attestedKeys.size());
            assertTrue(attestedKeys.stream().anyMatch(k -> k.getKeyId().equals(proofJwk1.getKeyId())));
            assertTrue(attestedKeys.stream().anyMatch(k -> k.getKeyId().equals(proofJwk2.getKeyId())));
        } catch (Exception e) {
            fail("Test should not throw exception: " + e.getMessage());
        }
    };

    private static void runAttestationWithX5cCertificateChain(KeycloakSession session) {
        try {
            KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
            X509Certificate cert = createTestCertificate(keyPair);
            List<X509Certificate> x5c = List.of(cert);

            KeyWrapper proofKey = getECKey("proofKey");
            String cNonce = getCNonce();

            // Create signer context from the private key
            KeyWrapper signerKey = new KeyWrapper();
            signerKey.setPrivateKey(keyPair.getPrivate());
            signerKey.setAlgorithm("ES256");
            signerKey.setType(KeyType.EC);

            // Create a custom truststore that includes our test certificate
            KeyStore customTrustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            customTrustStore.load(null, null);
            customTrustStore.setCertificateEntry("test-cert", cert);

            // Create a key resolver that trusts our certificate
            AttestationKeyResolver keyResolver = new StaticAttestationKeyResolver(Map.of());
            session.getProvider(TruststoreProvider.class);

            String attestationJwt = new JWSBuilder()
                    .type(AttestationValidatorUtil.ATTESTATION_JWT_TYP)
                    .x5c(x5c)
                    .jsonContent(createAttestationPayload(JWKBuilder.create().ec(proofKey.getPublicKey()), cNonce))
                    .sign(new ECDSASignatureSignerContext(signerKey));

            VCIssuanceContext vcIssuanceContext = createVCIssuanceContext(session);
            vcIssuanceContext.getCredentialRequest().setProof(new AttestationProof(attestationJwt));

            AttestationProofValidator validator = new AttestationProofValidator(session, keyResolver);
            List<JWK> attestedKeys = validator.validateProof(vcIssuanceContext);

            assertFalse(attestedKeys.isEmpty());
        } catch (Exception e) {
            fail("Test should not throw exception: " + e.getMessage());
        }
    }

    private static void runAttestationWithInvalidResistanceLevels(KeycloakSession session) {
        KeyWrapper attestationKey = getECKey("attestationKey");
        KeyWrapper proofKey = getECKey("proofKey");
        String cNonce = getCNonce();

        JWK proofJwk = JWKBuilder.create().ec(proofKey.getPublicKey());
        proofJwk.setKeyId(proofKey.getKid());

        Map<String, Object> payload = createAttestationPayload(proofJwk, cNonce);
        payload.put("key_storage", List.of("INVALID_LEVEL"));

        String attestationJwt = new JWSBuilder()
                .type(AttestationValidatorUtil.ATTESTATION_JWT_TYP)
                .kid(attestationKey.getKid())
                .jsonContent(payload)
                .sign(new ECDSASignatureSignerContext(attestationKey));

        VCIssuanceContext vcIssuanceContext = createVCIssuanceContext(session);
        vcIssuanceContext.getCredentialRequest().setProof(new AttestationProof(attestationJwt));

        AttestationKeyResolver keyResolver = new StaticAttestationKeyResolver(
                Map.of(attestationKey.getKid(), JWKBuilder.create().ec(attestationKey.getPublicKey()))
        );

        try {
            new AttestationProofValidator(session, keyResolver).validateProof(vcIssuanceContext);
            fail("Expected VCIssuerException for invalid resistance level");
        } catch (VCIssuerException e) {
            assertTrue("Expected error about invalid level but got: " + e.getMessage(),
                    e.getMessage().contains("key_storage") ||
                            e.getMessage().contains("resistance level") ||
                            e.getMessage().contains("INVALID_LEVEL"));
        }
    }

    private static void runAttestationWithExpiredCNonce(KeycloakSession session) {
        try {
            // Force expiration by setting negative lifetime
            session.getContext().getRealm()
                    .setAttribute(Oid4VciConstants.C_NONCE_LIFETIME_IN_SECONDS, -1);

            KeyWrapper attestationKey = getECKey("attestationKey");
            KeyWrapper proofKey = getECKey("proofKey");
            CNonceHandler cNonceHandler = session.getProvider(CNonceHandler.class);
            String cNonce = cNonceHandler.buildCNonce(
                    List.of(OID4VCIssuerWellKnownProvider.getCredentialsEndpoint(session.getContext())),
                    Map.of(JwtCNonceHandler.SOURCE_ENDPOINT,
                            OID4VCIssuerWellKnownProvider.getNonceEndpoint(session.getContext()))
            );

            // Wait to ensure expiration
            Thread.sleep(1000);

            String attestationJwt = createValidAttestationJwt(session, attestationKey,
                    JWKBuilder.create().ec(proofKey.getPublicKey()), cNonce);

            VCIssuanceContext vcIssuanceContext = createVCIssuanceContext(session);
            vcIssuanceContext.getCredentialRequest().setProof(new AttestationProof(attestationJwt));

            AttestationProofValidator validator = new AttestationProofValidator(session,
                    new StaticAttestationKeyResolver(
                            Map.of(attestationKey.getKid(), JWKBuilder.create().ec(attestationKey.getPublicKey()))
                    ));

            validator.validateProof(vcIssuanceContext);
            fail("Expected VCIssuerException for expired c_nonce");
        } catch (VCIssuerException e) {
            assertTrue(e.getMessage().contains("c_nonce not valid"));
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } finally {
            // Reset to default
            session.getContext().getRealm()
                    .removeAttribute(Oid4VciConstants.C_NONCE_LIFETIME_IN_SECONDS);
        }
    };

    private static void runAttestationWithMissingAttestedKeys(KeycloakSession session) {
        try {
            KeyWrapper attestationKey = getECKey("attestationKey");
            String cNonce = getCNonce();

            // Create minimal valid payload without attested_keys
            KeyAttestationJwtBody payload = new KeyAttestationJwtBody();
            payload.setIat((long) TIME_PROVIDER.currentTimeSeconds());
            payload.setNonce(cNonce);

            String attestationJwt = new JWSBuilder()
                    .type(AttestationValidatorUtil.ATTESTATION_JWT_TYP)
                    .kid(attestationKey.getKid())
                    .jsonContent(payload)
                    .sign(new ECDSASignatureSignerContext(attestationKey));

            VCIssuanceContext context = createVCIssuanceContext(session);
            context.getCredentialRequest().setProof(new AttestationProof(attestationJwt));

            AttestationProofValidator validator = new AttestationProofValidator(session,
                    new StaticAttestationKeyResolver(Map.of(attestationKey.getKid(),
                            JWKBuilder.create().ec(attestationKey.getPublicKey()))));

            validator.validateProof(context);
            fail("Expected VCIssuerException for missing attested_keys");
        } catch (VCIssuerException e) {
            assertTrue("Expected error about missing keys but got: " + e.getMessage(),
                    e.getMessage().contains("No valid attested keys") ||
                            e.getMessage().contains("attested_keys"));
        }
    }

    private static void runAttestationWithInvalidKeyType(KeycloakSession session) {
        KeyWrapper attestationKey = getECKey("attestationKey");
        String cNonce = getCNonce();

        // Create a more obviously invalid JWK structure
        Map<String, Object> invalidKey = new HashMap<>();
        invalidKey.put("kty", "INVALID_TYPE");
        invalidKey.put("kid", "invalid-key");
        // Missing required EC key parameters

        Map<String, Object> payload = new HashMap<>();
        payload.put("iat", TIME_PROVIDER.currentTimeSeconds());
        payload.put("nonce", cNonce);
        payload.put("attested_keys", List.of(invalidKey));

        String attestationJwt = new JWSBuilder()
                .type(AttestationValidatorUtil.ATTESTATION_JWT_TYP)
                .kid(attestationKey.getKid())
                .jsonContent(payload)
                .sign(new ECDSASignatureSignerContext(attestationKey));

        VCIssuanceContext vcIssuanceContext = createVCIssuanceContext(session);
        vcIssuanceContext.getCredentialRequest().setProof(new AttestationProof(attestationJwt));

        AttestationKeyResolver keyResolver = new StaticAttestationKeyResolver(
                Map.of(attestationKey.getKid(), JWKBuilder.create().ec(attestationKey.getPublicKey()))
        );

        try {
            new AttestationProofValidator(session, keyResolver).validateProof(vcIssuanceContext);
            fail("Expected VCIssuerException for invalid key type");
        } catch (VCIssuerException e) {
            assertTrue("Expected error about invalid key but got: " + e.getMessage(),
                    e.getMessage().contains("Unsupported key type") ||
                            e.getMessage().contains("Invalid key") ||
                            e.getMessage().contains("INVALID_TYPE"));
        }
    }
}
