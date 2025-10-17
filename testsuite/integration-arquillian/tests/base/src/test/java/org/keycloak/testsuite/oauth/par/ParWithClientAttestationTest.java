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
package org.keycloak.testsuite.oauth.par;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.keycloak.common.Profile.Feature.CLIENT_ATTESTATION;
import static org.keycloak.testsuite.AbstractAdminTest.loadJson;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.infinispan.Cache;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import org.keycloak.common.Profile;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.Time;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.oauth.ClientAttestation;
import org.keycloak.representations.oauth.ClientAttestationPoP;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
import org.keycloak.testsuite.AssertEvents;
import org.keycloak.testsuite.arquillian.annotation.EnableFeature;
import org.keycloak.testsuite.client.policies.AbstractClientPoliciesTest;
import org.keycloak.testsuite.util.oauth.ParResponse;


/**
 * Test suite for Client Attestation with PAR endpoint as per draft-ietf-oauth-attestation-based-client-auth-07
 *
 * @author <a href="mailto:Forkim.Akwichek@adorsys.com">Forkim Akwichek</a>
 */
@EnableFeature(value = CLIENT_ATTESTATION, skipRestart = true)
public class ParWithClientAttestationTest extends AbstractClientPoliciesTest {

    @Rule
    public AssertEvents events = new AssertEvents(this);

    private static final String CLIENT_NAME = "test-client-attestation";
    private static final String CLIENT_REDIRECT_URI = "https://client.example.com/callback";

    private KeyPair attestationKeyPair;
    private KeyPair clientKeyPair;
    private String trustedAttesterConfig;
    private HttpServer mockJwksServer;
    private ExecutorService serverExecutor;

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        RealmRepresentation realm = loadJson(getClass().getResourceAsStream("/testrealm.json"), RealmRepresentation.class);
        testRealms.add(realm);
    }

    @Before
    public void setupClientAttestation() throws Exception {
        // Clean up any existing state first
        if (mockJwksServer != null) {
            mockJwksServer.stop(0);
        }
        if (serverExecutor != null) {
            serverExecutor.shutdown();
            try {
                if (!serverExecutor.awaitTermination(1, TimeUnit.SECONDS)) {
                    serverExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                serverExecutor.shutdownNow();
            }
        }

        // Generate new key pairs for each test to avoid shared state
        attestationKeyPair = KeyUtils.generateRsaKeyPair(2048);
        clientKeyPair = KeyUtils.generateRsaKeyPair(2048);

        // Start mock JWKS server
        startMockJwksServer();
        
        // Use the mock server URL
        trustedAttesterConfig = "http://localhost:8080";
        
        // Enable client attestation feature and configure trusted attesters
        RealmRepresentation realm = adminClient.realm(oauth.getRealm()).toRepresentation();
        realm.getAttributes().put("client-attestation.trusted-attesters", trustedAttesterConfig);
        adminClient.realm(oauth.getRealm()).update(realm);
        
        
        // Verify the feature is enabled
        assertTrue("CLIENT_ATTESTATION feature should be enabled", 
                Profile.isFeatureEnabled(Profile.Feature.CLIENT_ATTESTATION));
    }

    @After
    public void cleanup() {
        // Clear caches to prevent test interference
        try {
            if (testingClient != null) {
                testingClient.server("test").run(session -> {
                    InfinispanConnectionProvider connections = session.getProvider(InfinispanConnectionProvider.class);
                    if (connections != null) {
                        // Clear replay protection cache
                        Cache<String, Object> actionTokenCache = connections.getCache(InfinispanConnectionProvider.ACTION_TOKEN_CACHE);
                        if (actionTokenCache != null) {
                            actionTokenCache.clear();
                        }
                        
                        // Clear JWKS key cache to prevent cached keys from interfering with subsequent tests
                        Cache<String, Object> keysCache = connections.getCache(InfinispanConnectionProvider.KEYS_CACHE_NAME);
                        if (keysCache != null) {
                            keysCache.clear();
                        }
                    }
                });
            }
        } catch (Exception e) {
            // Ignore if session is not available
        }

        if (mockJwksServer != null) {
            mockJwksServer.stop(0);
        }
        if (serverExecutor != null) {
            serverExecutor.shutdown();
            try {
                if (!serverExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    serverExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                serverExecutor.shutdownNow();
            }
        }
    }

    @Test
    public void testClientAttestationFeatureEnabled() {
        // Verify that the CLIENT_ATTESTATION feature is properly enabled
        assertTrue("CLIENT_ATTESTATION feature should be enabled",
                Profile.isFeatureEnabled(Profile.Feature.CLIENT_ATTESTATION));
    }

    @Test
    public void testSuccessfulParWithClientAttestation() throws Exception {
        // Create client with PAR requirement
        String clientId = createClientDynamically(generateSuffixedName(CLIENT_NAME), (OIDCClientRepresentation clientRep) -> {
            clientRep.setRequirePushedAuthorizationRequests(Boolean.TRUE);
            clientRep.setRedirectUris(new ArrayList<String>(Arrays.asList(CLIENT_REDIRECT_URI)));
        });
        OIDCClientRepresentation oidcCRep = getClientDynamically(clientId);
        String clientSecret = oidcCRep.getClientSecret();

        // Generate valid client attestation and PoP
        String attestationJwt = createValidClientAttestation(clientId);
        String attestationPoPJwt = createValidClientAttestationPoP(attestationJwt);

        // Perform PAR request with client attestation headers
        oauth.client(clientId, clientSecret);
        oauth.redirectUri(CLIENT_REDIRECT_URI);

        // Execute PAR request with client attestation headers
        ParResponse parResponse = oauth.pushedAuthorizationRequest()
                .clientAttestation(attestationJwt)
                .clientAttestationPoP(attestationPoPJwt)
                .send();

        // Verify successful response
        assertEquals(201, parResponse.getStatusCode());
        assertNotNull(parResponse.getRequestUri());
        assertTrue(parResponse.getExpiresIn() > 0);
    }

    @Test
    public void testParWithInvalidAttestationType() throws Exception {
        String clientId = createClientDynamically(generateSuffixedName(CLIENT_NAME), (OIDCClientRepresentation clientRep) -> {
            clientRep.setRequirePushedAuthorizationRequests(Boolean.TRUE);
            clientRep.setRedirectUris(new ArrayList<String>(Arrays.asList(CLIENT_REDIRECT_URI)));
        });
        OIDCClientRepresentation oidcCRep = getClientDynamically(clientId);
        String clientSecret = oidcCRep.getClientSecret();

        // Create attestation with wrong type
        String invalidAttestationJwt = createInvalidTypeClientAttestation(clientId);
        String attestationPoPJwt = createValidClientAttestationPoP(invalidAttestationJwt);

        oauth.client(clientId, clientSecret);
        oauth.redirectUri(CLIENT_REDIRECT_URI);

        ParResponse parResponse = oauth.pushedAuthorizationRequest()
                .clientAttestation(invalidAttestationJwt)
                .clientAttestationPoP(attestationPoPJwt)
                .send();

        // Verify the request failed with appropriate error
        assertEquals("Expected 400 status code for invalid attestation type", 400, parResponse.getStatusCode());
        assertEquals("Expected invalid_client error", "invalid_client", parResponse.getError());
    }

    @Test
    public void testParWithInvalidPoPType() throws Exception {
        String clientId = createClientDynamically(generateSuffixedName(CLIENT_NAME), (OIDCClientRepresentation clientRep) -> {
            clientRep.setRequirePushedAuthorizationRequests(Boolean.TRUE);
            clientRep.setRedirectUris(new ArrayList<String>(Arrays.asList(CLIENT_REDIRECT_URI)));
        });
        OIDCClientRepresentation oidcCRep = getClientDynamically(clientId);
        String clientSecret = oidcCRep.getClientSecret();

        String attestationJwt = createValidClientAttestation(clientId);
        String invalidPoPJwt = createInvalidTypeClientAttestationPoP(clientId);

        oauth.client(clientId, clientSecret);
        oauth.redirectUri(CLIENT_REDIRECT_URI);

        ParResponse parResponse = oauth.pushedAuthorizationRequest()
                .clientAttestation(attestationJwt)
                .clientAttestationPoP(invalidPoPJwt)
                .send();

        // Verify the request failed with appropriate error
        assertEquals("Expected 400 status code for invalid PoP type", 400, parResponse.getStatusCode());
        assertEquals("Expected invalid_client error", "invalid_client", parResponse.getError());
    }

    @Test
    public void testParWithExpiredAttestation() throws Exception {
        String clientId = createClientDynamically(generateSuffixedName(CLIENT_NAME), (OIDCClientRepresentation clientRep) -> {
            clientRep.setRequirePushedAuthorizationRequests(Boolean.TRUE);
            clientRep.setRedirectUris(new ArrayList<String>(Arrays.asList(CLIENT_REDIRECT_URI)));
        });
        OIDCClientRepresentation oidcCRep = getClientDynamically(clientId);
        String clientSecret = oidcCRep.getClientSecret();

        // Create expired attestation
        String expiredAttestationJwt = createExpiredClientAttestation(clientId);
        String attestationPoPJwt = createValidClientAttestationPoP(expiredAttestationJwt);

        oauth.client(clientId, clientSecret);
        oauth.redirectUri(CLIENT_REDIRECT_URI);

        ParResponse parResponse = oauth.pushedAuthorizationRequest()
                .clientAttestation(expiredAttestationJwt)
                .clientAttestationPoP(attestationPoPJwt)
                .send();

        // Verify the request failed with appropriate error
        assertEquals("Expected 400 status code for expired attestation", 400, parResponse.getStatusCode());
        assertEquals("Expected invalid_client error", "invalid_client", parResponse.getError());
        assertTrue("Expected error description to contain 'Client Attestation has expired'. Got: " + parResponse.getErrorDescription(),
                parResponse.getErrorDescription() != null &&
                        parResponse.getErrorDescription().contains("Client Attestation has expired"));
    }

    @Test
    public void testParWithReplayAttack() throws Exception {
        String clientId = createClientDynamically(generateSuffixedName(CLIENT_NAME), (OIDCClientRepresentation clientRep) -> {
            clientRep.setRequirePushedAuthorizationRequests(Boolean.TRUE);
            clientRep.setRedirectUris(new ArrayList<String>(Arrays.asList(CLIENT_REDIRECT_URI)));
        });
        OIDCClientRepresentation oidcCRep = getClientDynamically(clientId);
        String clientSecret = oidcCRep.getClientSecret();

        String attestationJwt = createValidClientAttestation(clientId);
        String attestationPoPJwt = createValidClientAttestationPoP(attestationJwt);

        oauth.client(clientId, clientSecret);
        oauth.redirectUri(CLIENT_REDIRECT_URI);

        // First request should succeed
        ParResponse response1 = oauth.pushedAuthorizationRequest()
                .clientAttestation(attestationJwt)
                .clientAttestationPoP(attestationPoPJwt)
                .send();

        assertEquals(201, response1.getStatusCode());

        // Second request with same PoP should fail (replay attack)
        ParResponse response2 = oauth.pushedAuthorizationRequest()
                .clientAttestation(attestationJwt)
                .clientAttestationPoP(attestationPoPJwt)
                .send();

        // Verify the request failed with appropriate error
        assertEquals("Expected 400 status code for replay attack", 400, response2.getStatusCode());
        assertEquals("Expected invalid_client error", "invalid_client", response2.getError());
    }

    @Test
    public void testParWithSymmetricAlgorithm() throws Exception {
        String clientId = createClientDynamically(generateSuffixedName(CLIENT_NAME), (OIDCClientRepresentation clientRep) -> {
            clientRep.setRequirePushedAuthorizationRequests(Boolean.TRUE);
            clientRep.setRedirectUris(new ArrayList<String>(Arrays.asList(CLIENT_REDIRECT_URI)));
        });
        OIDCClientRepresentation oidcCRep = getClientDynamically(clientId);
        String clientSecret = oidcCRep.getClientSecret();

        // Create attestation with symmetric algorithm (should fail)
        String invalidAttestationJwt = createSymmetricAlgorithmAttestation(clientId);
        String attestationPoPJwt = createValidClientAttestationPoP(invalidAttestationJwt);

        oauth.client(clientId, clientSecret);
        oauth.redirectUri(CLIENT_REDIRECT_URI);

        ParResponse parResponse = oauth.pushedAuthorizationRequest()
                .clientAttestation(invalidAttestationJwt)
                .clientAttestationPoP(attestationPoPJwt)
                .send();

        // Verify the request failed with appropriate error
        assertEquals("Expected 400 status code for symmetric algorithm", 400, parResponse.getStatusCode());
        assertEquals("Expected invalid_client error", "invalid_client", parResponse.getError());
    }

    // Helper methods

    private void startMockJwksServer() throws Exception {
        mockJwksServer = HttpServer.create(new InetSocketAddress(8080), 0);
        serverExecutor = Executors.newFixedThreadPool(1);
        mockJwksServer.setExecutor(serverExecutor);

        // Create JWKS response with the attester's public key
        String jwksResponse = createJwksResponse();

        mockJwksServer.createContext("/.well-known/jwks.json", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, jwksResponse.length());
                exchange.getResponseBody().write(jwksResponse.getBytes());
                exchange.close();
            }
        });

        mockJwksServer.start();
        
        // Give the server a moment to start up
        Thread.sleep(100);
    }

    private String createJwksResponse() throws Exception {
        // Get the RSA public key and extract modulus and exponent
        java.security.interfaces.RSAPublicKey rsaPublicKey = (java.security.interfaces.RSAPublicKey) attestationKeyPair.getPublic();

        // Convert BigInteger to Base64URL encoded strings
        String modulus = Base64Url.encode(rsaPublicKey.getModulus().toByteArray());
        String exponent = Base64Url.encode(rsaPublicKey.getPublicExponent().toByteArray());

        // Create JWKS response
        return "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"attester-key\",\"use\":\"sig\",\"n\":\"" +
                modulus + "\",\"e\":\"" + exponent + "\"}]}";
    }

    private String createValidClientAttestation(String clientId) throws Exception {
        ClientAttestation attestation = new ClientAttestation();
        attestation.issuer(trustedAttesterConfig); // Use the mock server URL
        attestation.subject(clientId); // Use the actual client ID
        attestation.iat((long) Time.currentTime());
        attestation.exp((long) (Time.currentTime() + 3600));

        // Create JWK for client key using JWKBuilder
        java.security.interfaces.RSAPublicKey clientRsaKey = (java.security.interfaces.RSAPublicKey) clientKeyPair.getPublic();
        org.keycloak.jose.jwk.JWK clientJwk = org.keycloak.jose.jwk.JWKBuilder.create()
                .kid(UUID.randomUUID().toString())
                .algorithm("RS256")
                .rsa(clientRsaKey, java.util.Collections.emptyList(), org.keycloak.crypto.KeyUse.SIG);

        // Set confirmation claim
        ClientAttestation.Confirmation confirmation = new ClientAttestation.Confirmation();
        confirmation.setJwk(clientJwk);
        attestation.setConfirmation(confirmation);

        // Sign with attester key
        return new JWSBuilder()
                .type("oauth-client-attestation+jwt")
                .kid("attester-key")
                .jsonContent(attestation)
                .rsa256(attestationKeyPair.getPrivate());
    }

    private String createValidClientAttestationPoP(String attestationJwt) throws Exception {
        // Parse attestation to get client key
        JWSInput attestationInput = new JWSInput(attestationJwt);
        ClientAttestation attestation = attestationInput.readJsonContent(ClientAttestation.class);

        ClientAttestationPoP attestationPoP = new ClientAttestationPoP();
        attestationPoP.issuer(attestation.getSubject()); // Use the client ID from attestation
        // Use the actual Keycloak server base URI as audience
        attestationPoP.audience(getAuthServerRoot().toString());
        attestationPoP.iat((long) Time.currentTime());
        attestationPoP.exp((long) (Time.currentTime() + 300));
        attestationPoP.id(UUID.randomUUID().toString());

        // Sign with client key
        return new JWSBuilder()
                .type("oauth-client-attestation-pop+jwt")
                .jsonContent(attestationPoP)
                .rsa256(clientKeyPair.getPrivate());
    }

    private String createInvalidTypeClientAttestation(String clientId) throws Exception {
        ClientAttestation attestation = new ClientAttestation();
        attestation.issuer(trustedAttesterConfig); // Use the mock server URL
        attestation.subject(clientId); // Use the actual client ID
        attestation.iat((long) Time.currentTime());
        attestation.exp((long) (Time.currentTime() + 3600));

        // Create JWK for client key using JWKBuilder
        java.security.interfaces.RSAPublicKey clientRsaKey = (java.security.interfaces.RSAPublicKey) clientKeyPair.getPublic();
        org.keycloak.jose.jwk.JWK clientJwk = org.keycloak.jose.jwk.JWKBuilder.create()
                .kid(UUID.randomUUID().toString())
                .algorithm("RS256")
                .rsa(clientRsaKey, java.util.Collections.emptyList(), org.keycloak.crypto.KeyUse.SIG);

        ClientAttestation.Confirmation confirmation = new ClientAttestation.Confirmation();
        confirmation.setJwk(clientJwk);
        attestation.setConfirmation(confirmation);

        // Wrong type
        return new JWSBuilder()
                .type("invalid-type")
                .kid("attester-key")
                .jsonContent(attestation)
                .rsa256(attestationKeyPair.getPrivate());
    }

    private String createInvalidTypeClientAttestationPoP(String clientId) throws Exception {
        ClientAttestationPoP attestationPoP = new ClientAttestationPoP();
        attestationPoP.issuer(clientId); // Use the actual client ID
        // Use the actual Keycloak server base URI as audience
        attestationPoP.audience(getAuthServerRoot().toString());
        attestationPoP.iat((long) Time.currentTime());
        attestationPoP.exp((long) (Time.currentTime() + 300));
        attestationPoP.id(UUID.randomUUID().toString());

        // Wrong type
        return new JWSBuilder()
                .type("invalid-type")
                .jsonContent(attestationPoP)
                .rsa256(clientKeyPair.getPrivate());
    }

    private String createExpiredClientAttestation(String clientId) throws Exception {
        ClientAttestation attestation = new ClientAttestation();
        attestation.issuer(trustedAttesterConfig); // Use the mock server URL
        attestation.subject(clientId); // Use the actual client ID
        attestation.iat((long) (Time.currentTime() - 3600)); // 1 hour ago
        attestation.exp((long) (Time.currentTime() - 1800)); // 30 minutes ago (expired)

        // Create JWK for client key using JWKBuilder
        java.security.interfaces.RSAPublicKey clientRsaKey = (java.security.interfaces.RSAPublicKey) clientKeyPair.getPublic();
        org.keycloak.jose.jwk.JWK clientJwk = org.keycloak.jose.jwk.JWKBuilder.create()
                .kid(UUID.randomUUID().toString())
                .algorithm("RS256")
                .rsa(clientRsaKey, java.util.Collections.emptyList(), org.keycloak.crypto.KeyUse.SIG);

        ClientAttestation.Confirmation confirmation = new ClientAttestation.Confirmation();
        confirmation.setJwk(clientJwk);
        attestation.setConfirmation(confirmation);

        return new JWSBuilder()
                .type("oauth-client-attestation+jwt")
                .kid("attester-key")
                .jsonContent(attestation)
                .rsa256(attestationKeyPair.getPrivate());
    }

    private String createSymmetricAlgorithmAttestation(String clientId) throws Exception {
        ClientAttestation attestation = new ClientAttestation();
        attestation.issuer(trustedAttesterConfig); // Use the mock server URL
        attestation.subject(clientId); // Use the actual client ID
        attestation.iat((long) Time.currentTime());
        attestation.exp((long) (Time.currentTime() + 3600));

        // Create JWK for client key using JWKBuilder
        java.security.interfaces.RSAPublicKey clientRsaKey = (java.security.interfaces.RSAPublicKey) clientKeyPair.getPublic();
        org.keycloak.jose.jwk.JWK clientJwk = org.keycloak.jose.jwk.JWKBuilder.create()
                .kid(UUID.randomUUID().toString())
                .algorithm("RS256")
                .rsa(clientRsaKey, java.util.Collections.emptyList(), org.keycloak.crypto.KeyUse.SIG);

        ClientAttestation.Confirmation confirmation = new ClientAttestation.Confirmation();
        confirmation.setJwk(clientJwk);
        attestation.setConfirmation(confirmation);

        // Use symmetric algorithm (should fail)
        return new JWSBuilder()
                .type("oauth-client-attestation+jwt")
                .kid("attester-key")
                .jsonContent(attestation)
                .hmac256("secret".getBytes());
    }
}
