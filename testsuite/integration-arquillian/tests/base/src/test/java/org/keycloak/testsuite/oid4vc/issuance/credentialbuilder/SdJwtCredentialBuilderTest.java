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

package org.keycloak.testsuite.oid4vc.issuance.credentialbuilder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.junit.Test;
import org.keycloak.common.VerificationException;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.SdJwtCredentialBody;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.SdJwtCredentialBuilder;
import org.keycloak.protocol.oid4vc.model.CredentialBuildConfig;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.IssuerSignedJwtVerificationOpts;
import org.keycloak.sdjwt.vp.SdJwtVP;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.keycloak.protocol.oid4vc.issuance.credentialbuilder.SdJwtCredentialBuilder.ISSUER_CLAIM;
import static org.keycloak.protocol.oid4vc.issuance.credentialbuilder.SdJwtCredentialBuilder.VERIFIABLE_CREDENTIAL_TYPE_CLAIM;
import static org.keycloak.sdjwt.IssuerSignedJWT.CLAIM_NAME_SD_HASH_ALGORITHM;
import static org.keycloak.sdjwt.IssuerSignedJWT.CLAIM_NAME_SELECTIVE_DISCLOSURE;

/**
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtCredentialBuilderTest extends CredentialBuilderTest {

    @Test
    public void shouldBuildSdJwtCredentialSuccessfully() throws Exception {
        testSignSDJwtCredential(
                Map.of("id", String.format("uri:uuid:%s", UUID.randomUUID()),
                        "test", "test",
                        "arrayClaim", List.of("a", "b", "c")),
                0,
                List.of()
        );
    }

    @Test
    public void buildSdJwtCredential_WithDecoys() throws Exception {
        testSignSDJwtCredential(
                Map.of("id", String.format("uri:uuid:%s", UUID.randomUUID()),
                        "test", "test",
                        "arrayClaim", List.of("a", "b", "c")),
                6,
                List.of()
        );
    }

    @Test
    public void buildSdJwtCredential_WithVisibleClaims() throws Exception {
        testSignSDJwtCredential(
                Map.of("id", String.format("uri:uuid:%s", UUID.randomUUID()),
                        "test", "test",
                        "arrayClaim", List.of("a", "b", "c")),
                6,
                List.of("test")
        );
    }

    @Test
    public void buildSdJwtCredential_WithNoClaims() throws Exception {
        testSignSDJwtCredential(
                Map.of(),
                0,
                List.of()
        );
    }

    public static void testSignSDJwtCredential(Map<String, Object> claims, int decoys, List<String> visibleClaims)
            throws VerificationException {
        String issuerDid = TEST_DID.toString();
        CredentialBuildConfig credentialBuildConfig = new CredentialBuildConfig()
                .setCredentialIssuer(issuerDid)
                .setCredentialType("https://credentials.example.com/test-credential")
                .setTokenJwsType("example+sd-jwt")
                .setHashAlgorithm("sha-256")
                .setNumberOfDecoys(decoys)
                .setSdJwtVisibleClaims(visibleClaims);

        VerifiableCredential testCredential = getTestCredential(claims);
        SdJwtCredentialBody sdJwtCredentialBody = new SdJwtCredentialBuilder()
                .buildCredentialBody(testCredential, credentialBuildConfig);

        String sdJwtString = sdJwtCredentialBody.sign(exampleSigner());
        SdJwtVP sdJwt = SdJwtVP.of(sdJwtString);

        IssuerSignedJWT jwt = sdJwt.getIssuerSignedJWT();

        assertEquals("The issuer should be set in the token.",
                issuerDid,
                jwt.getPayload().get(ISSUER_CLAIM).asText());

        assertEquals("The type should be included",
                credentialBuildConfig.getCredentialType(),
                jwt.getPayload().get(VERIFIABLE_CREDENTIAL_TYPE_CLAIM).asText());

        assertEquals("The JWS token type should be included",
                credentialBuildConfig.getTokenJwsType(),
                jwt.getHeader().getType());

        ArrayNode sdArrayNode = (ArrayNode) jwt.getPayload().get(CLAIM_NAME_SELECTIVE_DISCLOSURE);
        if (sdArrayNode != null) {
            assertEquals("The algorithm should be included",
                    credentialBuildConfig.getHashAlgorithm(),
                    jwt.getPayload().get(CLAIM_NAME_SD_HASH_ALGORITHM).asText());
        }

        List<String> disclosed = sdJwt.getDisclosures().values().stream().toList();
        assertEquals("All undisclosed claims and decoys should be provided.",
                disclosed.size() + decoys, sdArrayNode == null ? 0 : sdArrayNode.size());

        visibleClaims.forEach(vc ->
                assertTrue("The visible claims should be present within the token.",
                        jwt.getPayload().has(vc))
        );

        // Will check disclosure conformity
        sdJwt.getSdJwtVerificationContext().verifyIssuance(
                List.of(exampleVerifier()),
                IssuerSignedJwtVerificationOpts.builder()
                        .withValidateIssuedAtClaim(false)
                        .withValidateNotBeforeClaim(false)
                        .withValidateExpirationClaim(false)
                        .build(),
                null
        );
    }

    @Test
    public void shouldIncludeExpClaimWhenExpirationDateIsSet() throws Exception {
        String issuerDid = TEST_DID.toString();
        CredentialBuildConfig credentialBuildConfig = new CredentialBuildConfig()
                .setCredentialIssuer(issuerDid)
                .setCredentialType("https://credentials.example.com/test-credential")
                .setTokenJwsType("example+sd-jwt")
                .setHashAlgorithm("sha-256")
                .setNumberOfDecoys(0)
                .setSdJwtVisibleClaims(List.of());

        // Create credential with expiration date
        VerifiableCredential testCredential = getTestCredential(Map.of());
        Instant expirationDate = Instant.ofEpochSecond(2000);
        testCredential.setExpirationDate(expirationDate);

        SdJwtCredentialBody sdJwtCredentialBody = new SdJwtCredentialBuilder()
                .buildCredentialBody(testCredential, credentialBuildConfig);

        String sdJwtString = sdJwtCredentialBody.sign(exampleSigner());
        SdJwtVP sdJwt = SdJwtVP.of(sdJwtString);
        IssuerSignedJWT jwt = sdJwt.getIssuerSignedJWT();

        // Verify exp claim is present and has correct value
        JsonNode expClaim = jwt.getPayload().get("exp");
        assertNotNull("exp claim should be present when expirationDate is set", expClaim);
        assertEquals("exp claim should be set to expiration date epoch seconds",
                expirationDate.getEpochSecond(), expClaim.asLong());
    }

    @Test
    public void shouldNormalizeIdxFieldFromStringToInteger() throws Exception {
        String issuerDid = TEST_DID.toString();
        CredentialBuildConfig credentialBuildConfig = new CredentialBuildConfig()
                .setCredentialIssuer(issuerDid)
                .setCredentialType("https://credentials.example.com/test-credential")
                .setTokenJwsType("example+sd-jwt")
                .setHashAlgorithm("sha-256")
                .setNumberOfDecoys(0)
                .setSdJwtVisibleClaims(List.of("status"));

        // Create credential with status list where idx is a string (as it might come from protocol mapper)
        Map<String, Object> statusList = new HashMap<>();
        statusList.put("idx", "0");  // String, not integer
        statusList.put("uri", "test-status-list-uri");

        Map<String, Object> status = new HashMap<>();
        status.put("status_list", statusList);

        Map<String, Object> claims = new HashMap<>();
        claims.put("status", status);

        VerifiableCredential testCredential = getTestCredential(claims);

        SdJwtCredentialBody sdJwtCredentialBody = new SdJwtCredentialBuilder()
                .buildCredentialBody(testCredential, credentialBuildConfig);

        String sdJwtString = sdJwtCredentialBody.sign(exampleSigner());
        SdJwtVP sdJwt = SdJwtVP.of(sdJwtString);
        IssuerSignedJWT jwt = sdJwt.getIssuerSignedJWT();

        // Verify idx is an integer, not a string
        JsonNode statusClaim = jwt.getPayload().get("status");
        assertNotNull("status claim should be present", statusClaim);

        JsonNode statusListClaim = statusClaim.get("status_list");
        assertNotNull("status_list claim should be present", statusListClaim);

        JsonNode idxClaim = statusListClaim.get("idx");
        assertNotNull("idx claim should be present", idxClaim);
        assertTrue("idx should be a number (integer), not a string", idxClaim.isNumber());
        assertEquals("idx should be 0 as integer", 0, idxClaim.asInt());
    }
}
