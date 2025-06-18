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
package org.keycloak.testsuite.oid4vc.issuance.signing;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.apache.commons.collections4.map.HashedMap;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Base64Url;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.OID4VCLoginProtocolFactory;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerEndpoint;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProvider;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProviderFactory;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.SdJwtCredentialBuilder;
import org.keycloak.protocol.oid4vc.issuance.mappers.OID4VCGeneratedIdMapper;
import org.keycloak.protocol.oid4vc.model.AuthorizationDetail;
import org.keycloak.protocol.oid4vc.model.AuthorizationDetailResponse;
import org.keycloak.protocol.oid4vc.model.CredentialIssuer;
import org.keycloak.protocol.oid4vc.model.CredentialOfferURI;
import org.keycloak.protocol.oid4vc.model.CredentialRequest;
import org.keycloak.protocol.oid4vc.model.CredentialResponse;
import org.keycloak.protocol.oid4vc.model.CredentialsOffer;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.protocol.oid4vc.model.Proof;
import org.keycloak.protocol.oid4vc.model.ProofType;
import org.keycloak.protocol.oid4vc.model.SupportedCredentialConfiguration;
import org.keycloak.protocol.oidc.grants.PreAuthorizedCodeGrantTypeFactory;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ComponentExportRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.testsuite.util.oauth.AuthorizationEndpointResponse;
import org.keycloak.testsuite.util.oauth.OAuthClient;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.temporal.ChronoUnit;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Endpoint test with sd-jwt specific config.
 *
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 */
public class OID4VCSdJwtIssuingEndpointTest extends OID4VCIssuerEndpointTest {

    private List<AuthorizationDetailResponse> parseAuthorizationDetails(String responseBody) throws IOException {
        Map<String, Object> responseMap = JsonSerialization.readValue(responseBody, new TypeReference<Map<String, Object>>() {
        });
        Object authDetailsObj = responseMap.get("authorization_details");
        assertNotNull("authorization_details should be present in the response", authDetailsObj);
        return JsonSerialization.readValue(
                JsonSerialization.writeValueAsString(authDetailsObj),
                new TypeReference<List<AuthorizationDetailResponse>>() {
                }
        );
    }

    private String getAccessToken(String responseBody) throws IOException {
        Map<String, Object> responseMap = JsonSerialization.readValue(responseBody, new TypeReference<Map<String, Object>>() {
        });
        String token = (String) responseMap.get("access_token");
        assertNotNull("Access token should be present", token);
        return token;
    }

    @Test
    public void testRequestTestCredential() {
        String token = getBearerToken(oauth);
        testingClient
                .server(TEST_REALM_NAME)
                .run(session -> testRequestTestCredential(session, token, null));
    }

    @Test
    public void testRequestTestCredentialWithKeybinding() {
        String token = getBearerToken(oauth);
        testingClient
                .server(TEST_REALM_NAME)
                .run((session -> {
                    Proof proof = new Proof()
                            .setProofType(ProofType.JWT)
                            .setJwt(generateJwtProof(getCredentialIssuer(session), null));

                    SdJwtVP sdJwtVP = testRequestTestCredential(session, token, proof);
                    assertNotNull("A cnf claim must be attached to the credential", sdJwtVP.getCnfClaim());
                }));
    }

    @Test(expected = BadRequestException.class)
    public void testRequestTestCredentialWithInvalidKeybinding() throws Throwable {
        String token = getBearerToken(oauth);
        withCausePropagation(() ->
                testingClient
                        .server(TEST_REALM_NAME)
                        .run((session -> {
                                    Proof proof = new Proof()
                                            .setProofType(ProofType.JWT)
                                            .setJwt(generateInvalidJwtProof(getCredentialIssuer(session), null));

                                    testRequestTestCredential(session, token, proof);
                                })
                        )
        );
    }

    private static String getCredentialIssuer(KeycloakSession session) {
        return OID4VCIssuerWellKnownProvider.getIssuer(session.getContext());
    }

    private static SdJwtVP testRequestTestCredential(KeycloakSession session, String token, Proof proof)
            throws VerificationException {
        String vct = "https://credentials.example.com/test-credential";

        AppAuthManager.BearerTokenAuthenticator authenticator = new AppAuthManager.BearerTokenAuthenticator(session);
        authenticator.setTokenString(token);
        OID4VCIssuerEndpoint issuerEndpoint = prepareIssuerEndpoint(session, authenticator);

        CredentialRequest credentialRequest = new CredentialRequest()
                .setFormat(Format.SD_JWT_VC)
                .setVct(vct)
                .setProof(proof);

        Response credentialResponse = issuerEndpoint.requestCredential(credentialRequest);
        assertEquals("The credential request should be answered successfully.", HttpStatus.SC_OK, credentialResponse.getStatus());
        assertNotNull("A credential should be responded.", credentialResponse.getEntity());
        CredentialResponse credentialResponseVO = JsonSerialization.mapper.convertValue(credentialResponse.getEntity(), CredentialResponse.class);
        new TestCredentialResponseHandler(vct).handleCredentialResponse(credentialResponseVO);

        return SdJwtVP.of(credentialResponseVO.getCredential().toString());
    }

    // Tests the complete flow from
    // 1. Retrieving the credential-offer-uri
    // 2. Using the uri to get the actual credential offer
    // 3. Get the issuer metadata
    // 4. Get the openid-configuration
    // 5. Get an access token for the pre-authorized code
    // 6. Get the credential
    @Test
    public void testCredentialIssuance() throws Exception {

        String token = getBearerToken(oauth);

        // 1. Retrieving the credential-offer-uri
        HttpGet getCredentialOfferURI = new HttpGet(getBasePath(TEST_REALM_NAME) + "credential-offer-uri?credential_configuration_id=test-credential");
        getCredentialOfferURI.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        CloseableHttpResponse credentialOfferURIResponse = httpClient.execute(getCredentialOfferURI);

        assertEquals("A valid offer uri should be returned", HttpStatus.SC_OK, credentialOfferURIResponse.getStatusLine().getStatusCode());
        String s = IOUtils.toString(credentialOfferURIResponse.getEntity().getContent(), StandardCharsets.UTF_8);
        CredentialOfferURI credentialOfferURI = JsonSerialization.readValue(s, CredentialOfferURI.class);

        // 2. Using the uri to get the actual credential offer
        HttpGet getCredentialOffer = new HttpGet(credentialOfferURI.getIssuer() + "/" + credentialOfferURI.getNonce());
        getCredentialOffer.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        CloseableHttpResponse credentialOfferResponse = httpClient.execute(getCredentialOffer);

        assertEquals("A valid offer should be returned", HttpStatus.SC_OK, credentialOfferResponse.getStatusLine().getStatusCode());
        s = IOUtils.toString(credentialOfferResponse.getEntity().getContent(), StandardCharsets.UTF_8);
        CredentialsOffer credentialsOffer = JsonSerialization.readValue(s, CredentialsOffer.class);

        // 3. Get the issuer metadata
        HttpGet getIssuerMetadata = new HttpGet(credentialsOffer.getCredentialIssuer() + "/.well-known/openid-credential-issuer");
        CloseableHttpResponse issuerMetadataResponse = httpClient.execute(getIssuerMetadata);
        assertEquals(HttpStatus.SC_OK, issuerMetadataResponse.getStatusLine().getStatusCode());
        s = IOUtils.toString(issuerMetadataResponse.getEntity().getContent(), StandardCharsets.UTF_8);
        CredentialIssuer credentialIssuer = JsonSerialization.readValue(s, CredentialIssuer.class);

        assertEquals("We only expect one authorization server.", 1, credentialIssuer.getAuthorizationServers().size());

        // 4. Get the openid-configuration
        HttpGet getOpenidConfiguration = new HttpGet(credentialIssuer.getAuthorizationServers().get(0) + "/.well-known/openid-configuration");
        CloseableHttpResponse openidConfigResponse = httpClient.execute(getOpenidConfiguration);
        assertEquals(HttpStatus.SC_OK, openidConfigResponse.getStatusLine().getStatusCode());
        s = IOUtils.toString(openidConfigResponse.getEntity().getContent(), StandardCharsets.UTF_8);
        OIDCConfigurationRepresentation openidConfig = JsonSerialization.readValue(s, OIDCConfigurationRepresentation.class);

        assertNotNull("A token endpoint should be included.", openidConfig.getTokenEndpoint());
        assertTrue("The pre-authorized code should be supported.", openidConfig.getGrantTypesSupported().contains(PreAuthorizedCodeGrantTypeFactory.GRANT_TYPE));

        // 5. Get an access token for the pre-authorized code
        HttpPost postPreAuthorizedCode = new HttpPost(openidConfig.getTokenEndpoint());
        List<NameValuePair> parameters = new LinkedList<>();
        parameters.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, PreAuthorizedCodeGrantTypeFactory.GRANT_TYPE));
        parameters.add(new BasicNameValuePair(PreAuthorizedCodeGrantTypeFactory.CODE_REQUEST_PARAM, credentialsOffer.getGrants().getPreAuthorizedCode().getPreAuthorizedCode()));
        UrlEncodedFormEntity formEntity = new UrlEncodedFormEntity(parameters, StandardCharsets.UTF_8);
        postPreAuthorizedCode.setEntity(formEntity);
        AccessTokenResponse accessTokenResponse = new AccessTokenResponse(httpClient.execute(postPreAuthorizedCode));
        assertEquals(HttpStatus.SC_OK, accessTokenResponse.getStatusCode());
        String theToken = accessTokenResponse.getAccessToken();

        final String vct = "https://credentials.example.com/test-credential";

        // 6. Get the credential
        credentialsOffer.getCredentialConfigurationIds().stream()
                .map(offeredCredentialId -> credentialIssuer.getCredentialsSupported().get(offeredCredentialId))
                .forEach(supportedCredential -> {
                    try {
                        requestOffer(theToken, credentialIssuer.getCredentialEndpoint(), supportedCredential, new TestCredentialResponseHandler(vct));
                    } catch (IOException e) {
                        fail("Was not able to get the credential.");
                    } catch (VerificationException e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    /**
     * This is testing the configuration exposed by OID4VCIssuerWellKnownProvider based on the client and signing config setup here.
     */
    @Test
    public void getConfig() {
        String expectedIssuer = suiteContext.getAuthServerInfo().getContextRoot().toString() + "/auth/realms/" + TEST_REALM_NAME;
        String expectedCredentialsEndpoint = expectedIssuer + "/protocol/oid4vc/credential";
        final String expectedAuthorizationServer = expectedIssuer;
        testingClient
                .server(TEST_REALM_NAME)
                .run((session -> {
                    OID4VCIssuerWellKnownProvider oid4VCIssuerWellKnownProvider = new OID4VCIssuerWellKnownProvider(session);
                    Object issuerConfig = oid4VCIssuerWellKnownProvider.getConfig();
                    assertTrue("Valid credential-issuer metadata should be returned.", issuerConfig instanceof CredentialIssuer);
                    CredentialIssuer credentialIssuer = (CredentialIssuer) issuerConfig;
                    assertEquals("The correct issuer should be included.", expectedIssuer, credentialIssuer.getCredentialIssuer());
                    assertEquals("The correct credentials endpoint should be included.", expectedCredentialsEndpoint, credentialIssuer.getCredentialEndpoint());
                    assertEquals("Since the authorization server is equal to the issuer, just 1 should be returned.", 1, credentialIssuer.getAuthorizationServers().size());
                    assertEquals("The expected server should have been returned.", expectedAuthorizationServer, credentialIssuer.getAuthorizationServers().get(0));
                    assertTrue("The test-credential should be supported.", credentialIssuer.getCredentialsSupported().containsKey("test-credential"));
                    assertEquals("The test-credential should offer type test-credential", "test-credential", credentialIssuer.getCredentialsSupported().get("test-credential").getScope());
                    assertEquals("The test-credential should be offered in the sd-jwt format.", Format.SD_JWT_VC, credentialIssuer.getCredentialsSupported().get("test-credential").getFormat());
                    assertNotNull("The test-credential can optionally provide a claims claim.", credentialIssuer.getCredentialsSupported().get("test-credential").getClaims());
                    assertNotNull("The test-credential claim firstName is present.", credentialIssuer.getCredentialsSupported().get("test-credential").getClaims().get("firstName"));
                    assertFalse("The test-credential claim firstName is not mandatory.", credentialIssuer.getCredentialsSupported().get("test-credential").getClaims().get("firstName").getMandatory());
                    assertEquals("The test-credential claim firstName shall be displayed as First Name", "First Name", credentialIssuer.getCredentialsSupported().get("test-credential").getClaims().get("firstName").getDisplay().get(0).getName());
                    assertEquals("The test-credential should offer vct VerifiableCredential", "https://credentials.example.com/test-credential", credentialIssuer.getCredentialsSupported().get("test-credential").getVct());

                    // We are offering key binding only for identity credential
                    assertTrue("The IdentityCredential should contain a cryptographic binding method supported named jwk", credentialIssuer.getCredentialsSupported().get("IdentityCredential").getCryptographicBindingMethodsSupported().contains("jwk"));
                    assertTrue("The IdentityCredential should contain a credential signing algorithm named ES256", credentialIssuer.getCredentialsSupported().get("IdentityCredential").getCredentialSigningAlgValuesSupported().contains("ES256"));
                    assertEquals("The IdentityCredential should display as Test Credential", "Identity Credential", credentialIssuer.getCredentialsSupported().get("IdentityCredential").getDisplay().get(0).getName());
                    assertTrue("The IdentityCredential should support a proof of type jwt with signing algorithm ES256", credentialIssuer.getCredentialsSupported().get("IdentityCredential").getProofTypesSupported().getJwt().getProofSigningAlgValuesSupported().contains("ES256"));
                }));
    }

    protected static OID4VCIssuerEndpoint prepareIssuerEndpoint(KeycloakSession session, AppAuthManager.BearerTokenAuthenticator authenticator) {
        String issuerDid = "did:web:issuer.org";
        SdJwtCredentialBuilder testSdJwtCredentialBuilder = new SdJwtCredentialBuilder(issuerDid);

        return new OID4VCIssuerEndpoint(
                session,
                Map.of(
                        testSdJwtCredentialBuilder.getSupportedFormat(), testSdJwtCredentialBuilder
                ),
                authenticator,
                TIME_PROVIDER,
                30,
                true);
    }

    private static final String JTI_KEY = "jti";

    public static ProtocolMapperRepresentation getJtiGeneratedIdMapper(String supportedCredentialTypes) {
        ProtocolMapperRepresentation protocolMapperRepresentation = new ProtocolMapperRepresentation();
        protocolMapperRepresentation.setName("generated-id-mapper");
        protocolMapperRepresentation.setProtocol("oid4vc");
        protocolMapperRepresentation.setId(UUID.randomUUID().toString());
        protocolMapperRepresentation.setProtocolMapper("oid4vc-generated-id-mapper");
        protocolMapperRepresentation.setConfig(Map.of(
                OID4VCGeneratedIdMapper.SUBJECT_PROPERTY_CONFIG_KEY, JTI_KEY,
                "supportedCredentialTypes", supportedCredentialTypes
        ));
        return protocolMapperRepresentation;
    }

    @Override
    protected ComponentExportRepresentation getKeyProvider() {
        return getEcKeyProvider();
    }

    @Override
    protected List<ComponentExportRepresentation> getCredentialBuilderProviders() {
        return List.of(getCredentialBuilderProvider(Format.SD_JWT_VC));
    }

    @Override
    protected Map<String, String> getCredentialDefinitionAttributes() {
        Map<String, String> testCredentialAttributes = Map.ofEntries(
                Map.entry("vc.test-credential.expiry_in_s", "1800"),
                Map.entry("vc.test-credential.format", Format.SD_JWT_VC),
                Map.entry("vc.test-credential.scope", "test-credential"),
                Map.entry("vc.test-credential.claims", "{ \"firstName\": {\"mandatory\": false, \"display\": [{\"name\": \"First Name\", \"locale\": \"en-US\"}, {\"name\": \"名前\", \"locale\": \"ja-JP\"}]}, \"lastName\": {\"mandatory\": false}, \"email\": {\"mandatory\": false} }"),
                Map.entry("vc.test-credential.vct", "https://credentials.example.com/test-credential"),
                Map.entry("vc.test-credential.credential_signing_alg_values_supported", "ES256,ES384"),
                Map.entry("vc.test-credential.display.0", "{\n  \"name\": \"Test Credential\"\n}"),
                Map.entry("vc.test-credential.cryptographic_binding_methods_supported", "jwk"),
                Map.entry("vc.test-credential.proof_types_supported", "{\"jwt\":{\"proof_signing_alg_values_supported\":[\"ES256\"]}}"),
                Map.entry("vc.test-credential.credential_build_config.token_jws_type", "example+sd-jwt"),
                Map.entry("vc.test-credential.credential_build_config.hash_algorithm", "sha-256"),
                Map.entry("vc.test-credential.credential_build_config.visible_claims", "iat,nbf,jti"),
                Map.entry("vc.test-credential.credential_build_config.decoys", "2"),
                Map.entry("vc.test-credential.credential_build_config.signing_algorithm", "ES256")
        );

        Map<String, String> identityCredentialAttributes = Map.ofEntries(
                Map.entry("vc.IdentityCredential.expiry_in_s", "31536000"),
                Map.entry("vc.IdentityCredential.format", Format.SD_JWT_VC),
                Map.entry("vc.IdentityCredential.scope", "identity_credential"),
                Map.entry("vc.IdentityCredential.vct", "https://credentials.example.com/identity_credential"),
                Map.entry("vc.IdentityCredential.cryptographic_binding_methods_supported", "jwk"),
                Map.entry("vc.IdentityCredential.credential_signing_alg_values_supported", "ES256,ES384"),
                Map.entry("vc.IdentityCredential.claims", "{\"given_name\":{\"display\":[{\"name\":\"الاسم الشخصي\",\"locale\":\"ar\"},{\"name\":\"Vorname\",\"locale\":\"de\"},{\"name\":\"Given Name\",\"locale\":\"en\"},{\"name\":\"Nombre\",\"locale\":\"es\"},{\"name\":\"نام\",\"locale\":\"fa\"},{\"name\":\"Etunimi\",\"locale\":\"fi\"},{\"name\":\"Prénom\",\"locale\":\"fr\"},{\"name\":\"पहचानी गई नाम\",\"locale\":\"hi\"},{\"name\":\"Nome\",\"locale\":\"it\"},{\"name\":\"名\",\"locale\":\"ja\"},{\"name\":\"Овог нэр\",\"locale\":\"mn\"},{\"name\":\"Voornaam\",\"locale\":\"nl\"},{\"name\":\"Nome Próprio\",\"locale\":\"pt\"},{\"name\":\"Förnamn\",\"locale\":\"sv\"},{\"name\":\"مسلمان نام\",\"locale\":\"ur\"}]},\"family_name\":{\"display\":[{\"name\":\"اسم العائلة\",\"locale\":\"ar\"},{\"name\":\"Nachname\",\"locale\":\"de\"},{\"name\":\"Family Name\",\"locale\":\"en\"},{\"name\":\"Apellido\",\"locale\":\"es\"},{\"name\":\"نام خانوادگی\",\"locale\":\"fa\"},{\"name\":\"Sukunimi\",\"locale\":\"fi\"},{\"name\":\"Nom de famille\",\"locale\":\"fr\"},{\"name\":\"परिवार का नाम\",\"locale\":\"hi\"},{\"name\":\"Cognome\",\"locale\":\"it\"},{\"name\":\"姓\",\"locale\":\"ja\"},{\"name\":\"өөрийн нэр\",\"locale\":\"mn\"},{\"name\":\"Achternaam\",\"locale\":\"nl\"},{\"name\":\"Sobrenome\",\"locale\":\"pt\"},{\"name\":\"Efternamn\",\"locale\":\"sv\"},{\"name\":\"خاندانی نام\",\"locale\":\"ur\"}]},\"birthdate\":{\"display\":[{\"name\":\"تاريخ الميلاد\",\"locale\":\"ar\"},{\"name\":\"Geburtsdatum\",\"locale\":\"de\"},{\"name\":\"Date of Birth\",\"locale\":\"en\"},{\"name\":\"Fecha de Nacimiento\",\"locale\":\"es\"},{\"name\":\"تاریخ تولد\",\"locale\":\"fa\"},{\"name\":\"Syntymäaika\",\"locale\":\"fi\"},{\"name\":\"Date de naissance\",\"locale\":\"fr\"},{\"name\":\"जन्म की तारीख\",\"locale\":\"hi\"},{\"name\":\"Data di nascita\",\"locale\":\"it\"},{\"name\":\"生年月日\",\"locale\":\"ja\"},{\"name\":\"төрсөн өдөр\",\"locale\":\"mn\"},{\"name\":\"Geboortedatum\",\"locale\":\"nl\"},{\"name\":\"Data de Nascimento\",\"locale\":\"pt\"},{\"name\":\"Födelsedatum\",\"locale\":\"sv\"},{\"name\":\"تاریخ پیدائش\",\"locale\":\"ur\"}]}}"),
                Map.entry("vc.IdentityCredential.display.0", "{\"name\": \"Identity Credential\"}"),
                Map.entry("vc.IdentityCredential.proof_types_supported", "{\"jwt\":{\"proof_signing_alg_values_supported\":[\"ES256\"]}}"),
                Map.entry("vc.IdentityCredential.credential_build_config.token_jws_type", "example+sd-jwt"),
                Map.entry("vc.IdentityCredential.credential_build_config.hash_algorithm", "sha-256"),
                Map.entry("vc.IdentityCredential.credential_build_config.visible_claims", "iat,nbf,jti"),
                Map.entry("vc.IdentityCredential.credential_build_config.decoys", "0"),
                Map.entry("vc.IdentityCredential.credential_build_config.signing_algorithm", "ES256")
        );

        HashedMap<String, String> allAttributes = new HashedMap<>();
        allAttributes.putAll(testCredentialAttributes);
        allAttributes.putAll(identityCredentialAttributes);

        return allAttributes;
    }

    static class TestCredentialResponseHandler extends CredentialResponseHandler {
        final String vct;

        TestCredentialResponseHandler(String vct) {
            this.vct = vct;
        }

        @Override
        protected void handleCredentialResponse(CredentialResponse credentialResponse) throws VerificationException {
            // SDJWT have a special format.
            SdJwtVP sdJwtVP = SdJwtVP.of(credentialResponse.getCredential().toString());
            JsonWebToken jsonWebToken = TokenVerifier.create(sdJwtVP.getIssuerSignedJWT().toJws(), JsonWebToken.class).getToken();

            assertNotNull("A valid credential string should have been responded", jsonWebToken);
            assertNotNull("The credentials should include the id claim", jsonWebToken.getId());
            assertNotNull("The credentials should be included at the vct-claim.", jsonWebToken.getOtherClaims().get("vct"));
            assertEquals("The credentials should be included at the vct-claim.", vct, jsonWebToken.getOtherClaims().get("vct").toString());

            Map<String, JsonNode> disclosureMap = sdJwtVP.getDisclosures().values().stream()
                    .map(disclosure -> {
                        try {
                            JsonNode jsonNode = JsonSerialization.mapper.readTree(Base64Url.decode(disclosure));
                            return Map.entry(jsonNode.get(1).asText(), jsonNode); // Create a Map.Entry
                        } catch (IOException e) {
                            throw new RuntimeException(e); // Re-throw as unchecked exception
                        }
                    })
                    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            assertFalse("Only mappers supported for the requested type should have been evaluated.", disclosureMap.containsKey("given_name"));
            assertTrue("The credentials should include the firstName claim.", disclosureMap.containsKey("firstName"));
            assertEquals("firstName claim incorrectly mapped.", "John", disclosureMap.get("firstName").get(2).asText());
            assertTrue("The credentials should include the lastName claim.", disclosureMap.containsKey("lastName"));
            assertEquals("lastName claim incorrectly mapped.", "Doe", disclosureMap.get("lastName").get(2).asText());
            assertTrue("The credentials should include the roles claim.", disclosureMap.containsKey("roles"));
            assertTrue("The credentials should include the test-credential claim.", disclosureMap.containsKey("test-credential"));
            assertTrue("lastName claim incorrectly mapped.", disclosureMap.get("test-credential").get(2).asBoolean());
            assertTrue("The credentials should include the email claim.", disclosureMap.containsKey("email"));
            assertEquals("email claim incorrectly mapped.", "john@email.cz", disclosureMap.get("email").get(2).asText());

            assertNotNull("Test credential shall include an iat claim.", jsonWebToken.getIat());
            assertNotNull("Test credential shall include an nbf claim.", jsonWebToken.getNbf());
        }
    }

    @Test
    public void testPreAuthorizedCodeWithAuthorizationDetailsFormat() throws Exception {
        String token = getBearerToken(oauth);

        // 1. Retrieve the credential offer URI
        HttpGet getCredentialOfferURI = new HttpGet(getBasePath(TEST_REALM_NAME) + "credential-offer-uri?credential_configuration_id=test-credential");
        getCredentialOfferURI.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        CredentialOfferURI credentialOfferURI;
        try (CloseableHttpResponse response = httpClient.execute(getCredentialOfferURI)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            credentialOfferURI = JsonSerialization.readValue(s, CredentialOfferURI.class);
        }

        // 2. Get the credential offer
        HttpGet getCredentialOffer = new HttpGet(credentialOfferURI.getIssuer() + "/" + credentialOfferURI.getNonce());
        CredentialsOffer credentialsOffer;
        try (CloseableHttpResponse response = httpClient.execute(getCredentialOffer)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            credentialsOffer = JsonSerialization.readValue(s, CredentialsOffer.class);
        }

        // 3. Get the issuer metadata
        HttpGet getIssuerMetadata = new HttpGet(credentialsOffer.getCredentialIssuer() + "/.well-known/openid-credential-issuer");
        CredentialIssuer credentialIssuer;
        try (CloseableHttpResponse response = httpClient.execute(getIssuerMetadata)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            credentialIssuer = JsonSerialization.readValue(s, CredentialIssuer.class);
        }

        // 4. Get the openid-configuration
        HttpGet getOpenidConfiguration = new HttpGet(credentialIssuer.getAuthorizationServers().get(0) + "/.well-known/openid-configuration");
        OIDCConfigurationRepresentation openidConfig;
        try (CloseableHttpResponse response = httpClient.execute(getOpenidConfiguration)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            openidConfig = JsonSerialization.readValue(s, OIDCConfigurationRepresentation.class);
        }

        // 5. Prepare authorization_details
        AuthorizationDetail authDetail = new AuthorizationDetail();
        authDetail.setType("openid_credential");
        authDetail.setFormat("vc+sd-jwt");
        authDetail.setVct("https://credentials.example.com/test-credential");
        List<AuthorizationDetail> authDetails = List.of(authDetail);
        String authDetailsJson = JsonSerialization.writeValueAsString(authDetails);

        // 6. Get an access token with authorization_details
        HttpPost postPreAuthorizedCode = new HttpPost(openidConfig.getTokenEndpoint());
        List<NameValuePair> parameters = new LinkedList<>();
        parameters.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, PreAuthorizedCodeGrantTypeFactory.GRANT_TYPE));
        parameters.add(new BasicNameValuePair(PreAuthorizedCodeGrantTypeFactory.CODE_REQUEST_PARAM, credentialsOffer.getGrants().getPreAuthorizedCode().getPreAuthorizedCode()));
        parameters.add(new BasicNameValuePair("authorization_details", authDetailsJson));
        UrlEncodedFormEntity formEntity = new UrlEncodedFormEntity(parameters, StandardCharsets.UTF_8);
        postPreAuthorizedCode.setEntity(formEntity);
        try (CloseableHttpResponse tokenResponse = httpClient.execute(postPreAuthorizedCode)) {
            assertEquals(HttpStatus.SC_OK, tokenResponse.getStatusLine().getStatusCode());

            // 7. Read the response body
            String responseBody = IOUtils.toString(tokenResponse.getEntity().getContent(), StandardCharsets.UTF_8);

            // Parse authorization_details
            List<AuthorizationDetailResponse> authDetailsResponse = parseAuthorizationDetails(responseBody);
            assertNotNull("authorization_details should be present in the response", authDetailsResponse);
            assertEquals(1, authDetailsResponse.size());
            AuthorizationDetailResponse authDetailResponse = authDetailsResponse.get(0);
            assertEquals("openid_credential", authDetailResponse.getType());
            assertEquals("vc+sd-jwt", authDetailResponse.getFormat());
            assertEquals("https://credentials.example.com/test-credential", authDetailResponse.getVct());
            assertNotNull(authDetailResponse.getCredentialIdentifiers());
            assertFalse(authDetailResponse.getCredentialIdentifiers().isEmpty());

            // Extract access token
            String a_token = getAccessToken(responseBody);

            // 8. Request the credential
            final String vct = "https://credentials.example.com/test-credential";
            credentialsOffer.getCredentialConfigurationIds().stream()
                    .map(offeredCredentialId -> credentialIssuer.getCredentialsSupported().get(offeredCredentialId))
                    .forEach(supportedCredential -> {
                        try {
                            requestOffer(a_token, credentialIssuer.getCredentialEndpoint(), supportedCredential, new TestCredentialResponseHandler(vct));
                        } catch (IOException | VerificationException e) {
                            fail("Was not able to get the credential: " + e.getMessage());
                        }
                    });
        }
    }

    @Test
    public void testPreAuthorizedCodeWithInvalidAuthorizationDetails() throws Exception {
        String token = getBearerToken(oauth);

        // 1. Retrieve the credential offer URI
        HttpGet getCredentialOfferURI = new HttpGet(getBasePath(TEST_REALM_NAME) + "credential-offer-uri?credential_configuration_id=test-credential");
        getCredentialOfferURI.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        CredentialOfferURI credentialOfferURI;
        try (CloseableHttpResponse response = httpClient.execute(getCredentialOfferURI)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            credentialOfferURI = JsonSerialization.readValue(s, CredentialOfferURI.class);
        }

        // 2. Get the credential offer
        HttpGet getCredentialOffer = new HttpGet(credentialOfferURI.getIssuer() + "/" + credentialOfferURI.getNonce());
        CredentialsOffer credentialsOffer;
        try (CloseableHttpResponse response = httpClient.execute(getCredentialOffer)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            credentialsOffer = JsonSerialization.readValue(s, CredentialsOffer.class);
        }

        // 3. Get the issuer metadata
        HttpGet getIssuerMetadata = new HttpGet(credentialsOffer.getCredentialIssuer() + "/.well-known/openid-credential-issuer");
        CredentialIssuer credentialIssuer;
        try (CloseableHttpResponse response = httpClient.execute(getIssuerMetadata)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            credentialIssuer = JsonSerialization.readValue(s, CredentialIssuer.class);
        }

        // 4. Get the openid-configuration
        HttpGet getOpenidConfiguration = new HttpGet(credentialIssuer.getAuthorizationServers().get(0) + "/.well-known/openid-configuration");
        OIDCConfigurationRepresentation openidConfig;
        try (CloseableHttpResponse response = httpClient.execute(getOpenidConfiguration)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            openidConfig = JsonSerialization.readValue(s, OIDCConfigurationRepresentation.class);
        }

        // 5. Prepare invalid authorization_details
        AuthorizationDetail authDetail = new AuthorizationDetail();
        authDetail.setType("openid_credential");
        authDetail.setFormat("vc+sd-jwt");
        authDetail.setVct("https://credentials.example.com/test-credential");
        authDetail.setCredentialConfigurationId("test-credential"); // Invalid: credential_configuration_id should not be combined with format
        List<AuthorizationDetail> authDetails = List.of(authDetail);
        String authDetailsJson = JsonSerialization.writeValueAsString(authDetails);

        // 6. Attempt to get an access token with invalid authorization_details
        HttpPost postPreAuthorizedCode = new HttpPost(openidConfig.getTokenEndpoint());
        List<NameValuePair> parameters = new LinkedList<>();
        parameters.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, PreAuthorizedCodeGrantTypeFactory.GRANT_TYPE));
        parameters.add(new BasicNameValuePair(PreAuthorizedCodeGrantTypeFactory.CODE_REQUEST_PARAM, credentialsOffer.getGrants().getPreAuthorizedCode().getPreAuthorizedCode()));
        parameters.add(new BasicNameValuePair("authorization_details", authDetailsJson));
        UrlEncodedFormEntity formEntity = new UrlEncodedFormEntity(parameters, StandardCharsets.UTF_8);
        postPreAuthorizedCode.setEntity(formEntity);
        try (CloseableHttpResponse tokenResponse = httpClient.execute(postPreAuthorizedCode)) {
            assertEquals(HttpStatus.SC_BAD_REQUEST, tokenResponse.getStatusLine().getStatusCode());
        }
    }

    @Test
    public void testCredentialIdentifierPersistenceInSession() throws Exception {
        String token = getBearerToken(oauth);

        // Prepare authorization_details with credential_configuration_id
        AuthorizationDetail authDetail = new AuthorizationDetail();
        authDetail.setType("openid_credential");
        authDetail.setCredentialConfigurationId("test-credential");
        List<AuthorizationDetail> authDetails = List.of(authDetail);
        String authDetailsJson = JsonSerialization.writeValueAsString(authDetails);

        // First token request - should generate new identifier
        // Get a fresh credential offer URI for the first request
        HttpGet getCredentialOfferURI1 = new HttpGet(getBasePath(TEST_REALM_NAME) + "credential-offer-uri?credential_configuration_id=test-credential");
        getCredentialOfferURI1.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        CredentialOfferURI credentialOfferURI1;
        try (CloseableHttpResponse response = httpClient.execute(getCredentialOfferURI1)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            credentialOfferURI1 = JsonSerialization.readValue(s, CredentialOfferURI.class);
        }

        // Get the credential offer for the first request
        HttpGet getCredentialOffer1 = new HttpGet(credentialOfferURI1.getIssuer() + "/" + credentialOfferURI1.getNonce());
        CredentialsOffer credentialsOffer1;
        try (CloseableHttpResponse response = httpClient.execute(getCredentialOffer1)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            credentialsOffer1 = JsonSerialization.readValue(s, CredentialsOffer.class);
        }

        // Get the issuer metadata
        HttpGet getIssuerMetadata = new HttpGet(credentialsOffer1.getCredentialIssuer() + "/.well-known/openid-credential-issuer");
        CredentialIssuer credentialIssuer;
        try (CloseableHttpResponse response = httpClient.execute(getIssuerMetadata)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            credentialIssuer = JsonSerialization.readValue(s, CredentialIssuer.class);
        }

        // Get the openid-configuration
        HttpGet getOpenidConfiguration = new HttpGet(credentialIssuer.getAuthorizationServers().get(0) + "/.well-known/openid-configuration");
        OIDCConfigurationRepresentation openidConfig;
        try (CloseableHttpResponse response = httpClient.execute(getOpenidConfiguration)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            openidConfig = JsonSerialization.readValue(s, OIDCConfigurationRepresentation.class);
        }

        HttpPost postPreAuthorizedCode1 = new HttpPost(openidConfig.getTokenEndpoint());
        List<NameValuePair> parameters1 = new LinkedList<>();
        parameters1.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, PreAuthorizedCodeGrantTypeFactory.GRANT_TYPE));
        parameters1.add(new BasicNameValuePair(PreAuthorizedCodeGrantTypeFactory.CODE_REQUEST_PARAM, credentialsOffer1.getGrants().getPreAuthorizedCode().getPreAuthorizedCode()));
        parameters1.add(new BasicNameValuePair("authorization_details", authDetailsJson));
        UrlEncodedFormEntity formEntity1 = new UrlEncodedFormEntity(parameters1, StandardCharsets.UTF_8);
        postPreAuthorizedCode1.setEntity(formEntity1);

        String firstIdentifier = null;
        try (CloseableHttpResponse tokenResponse1 = httpClient.execute(postPreAuthorizedCode1)) {
            assertEquals(HttpStatus.SC_OK, tokenResponse1.getStatusLine().getStatusCode());
            String responseBody1 = IOUtils.toString(tokenResponse1.getEntity().getContent(), StandardCharsets.UTF_8);

            List<AuthorizationDetailResponse> authDetailsResponse1 = parseAuthorizationDetails(responseBody1);
            assertEquals(1, authDetailsResponse1.size());
            AuthorizationDetailResponse authDetailResponse1 = authDetailsResponse1.get(0);
            assertEquals("test-credential", authDetailResponse1.getCredentialConfigurationId());
            assertNotNull(authDetailResponse1.getCredentialIdentifiers());
            assertEquals(1, authDetailResponse1.getCredentialIdentifiers().size());
            firstIdentifier = authDetailResponse1.getCredentialIdentifiers().get(0);
            assertTrue("Identifier should start with credential_configuration_id", firstIdentifier.startsWith("test-credential-"));
        }

        // Second token request with same credential_configuration_id - should reuse the same identifier
        // Get a fresh credential offer URI for the second request
        HttpGet getCredentialOfferURI2 = new HttpGet(getBasePath(TEST_REALM_NAME) + "credential-offer-uri?credential_configuration_id=test-credential");
        getCredentialOfferURI2.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        CredentialOfferURI credentialOfferURI2;
        try (CloseableHttpResponse response = httpClient.execute(getCredentialOfferURI2)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            credentialOfferURI2 = JsonSerialization.readValue(s, CredentialOfferURI.class);
        }

        // Get the credential offer for the second request
        HttpGet getCredentialOffer2 = new HttpGet(credentialOfferURI2.getIssuer() + "/" + credentialOfferURI2.getNonce());
        CredentialsOffer credentialsOffer2;
        try (CloseableHttpResponse response = httpClient.execute(getCredentialOffer2)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            credentialsOffer2 = JsonSerialization.readValue(s, CredentialsOffer.class);
        }

        HttpPost postPreAuthorizedCode2 = new HttpPost(openidConfig.getTokenEndpoint());
        List<NameValuePair> parameters2 = new LinkedList<>();
        parameters2.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, PreAuthorizedCodeGrantTypeFactory.GRANT_TYPE));
        parameters2.add(new BasicNameValuePair(PreAuthorizedCodeGrantTypeFactory.CODE_REQUEST_PARAM, credentialsOffer2.getGrants().getPreAuthorizedCode().getPreAuthorizedCode()));
        parameters2.add(new BasicNameValuePair("authorization_details", authDetailsJson));
        UrlEncodedFormEntity formEntity2 = new UrlEncodedFormEntity(parameters2, StandardCharsets.UTF_8);
        postPreAuthorizedCode2.setEntity(formEntity2);

        try (CloseableHttpResponse tokenResponse2 = httpClient.execute(postPreAuthorizedCode2)) {
            assertEquals(HttpStatus.SC_OK, tokenResponse2.getStatusLine().getStatusCode());
            String responseBody2 = IOUtils.toString(tokenResponse2.getEntity().getContent(), StandardCharsets.UTF_8);

            List<AuthorizationDetailResponse> authDetailsResponse2 = parseAuthorizationDetails(responseBody2);
            assertEquals(1, authDetailsResponse2.size());
            AuthorizationDetailResponse authDetailResponse2 = authDetailsResponse2.get(0);
            assertEquals("test-credential", authDetailResponse2.getCredentialConfigurationId());
            assertNotNull(authDetailResponse2.getCredentialIdentifiers());
            assertEquals(1, authDetailResponse2.getCredentialIdentifiers().size());
            String secondIdentifier = authDetailResponse2.getCredentialIdentifiers().get(0);

            // Should be the same identifier as the first request
            assertEquals("Credential identifiers should be the same within the same session", firstIdentifier, secondIdentifier);
        }

        // Test with format-based authorization details - should generate different identifier
        // Get a fresh credential offer URI for the third request
        HttpGet getCredentialOfferURI3 = new HttpGet(getBasePath(TEST_REALM_NAME) + "credential-offer-uri?credential_configuration_id=test-credential");
        getCredentialOfferURI3.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        CredentialOfferURI credentialOfferURI3;
        try (CloseableHttpResponse response = httpClient.execute(getCredentialOfferURI3)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            credentialOfferURI3 = JsonSerialization.readValue(s, CredentialOfferURI.class);
        }

        // Get the credential offer for the third request
        HttpGet getCredentialOffer3 = new HttpGet(credentialOfferURI3.getIssuer() + "/" + credentialOfferURI3.getNonce());
        CredentialsOffer credentialsOffer3;
        try (CloseableHttpResponse response = httpClient.execute(getCredentialOffer3)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            credentialsOffer3 = JsonSerialization.readValue(s, CredentialsOffer.class);
        }

        AuthorizationDetail authDetailFormat = new AuthorizationDetail();
        authDetailFormat.setType("openid_credential");
        authDetailFormat.setFormat("vc+sd-jwt");
        authDetailFormat.setVct("https://credentials.example.com/test-credential");
        List<AuthorizationDetail> authDetailsFormat = List.of(authDetailFormat);
        String authDetailsFormatJson = JsonSerialization.writeValueAsString(authDetailsFormat);

        HttpPost postPreAuthorizedCode3 = new HttpPost(openidConfig.getTokenEndpoint());
        List<NameValuePair> parameters3 = new LinkedList<>();
        parameters3.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, PreAuthorizedCodeGrantTypeFactory.GRANT_TYPE));
        parameters3.add(new BasicNameValuePair(PreAuthorizedCodeGrantTypeFactory.CODE_REQUEST_PARAM, credentialsOffer3.getGrants().getPreAuthorizedCode().getPreAuthorizedCode()));
        parameters3.add(new BasicNameValuePair("authorization_details", authDetailsFormatJson));
        UrlEncodedFormEntity formEntity3 = new UrlEncodedFormEntity(parameters3, StandardCharsets.UTF_8);
        postPreAuthorizedCode3.setEntity(formEntity3);

        try (CloseableHttpResponse tokenResponse3 = httpClient.execute(postPreAuthorizedCode3)) {
            assertEquals(HttpStatus.SC_OK, tokenResponse3.getStatusLine().getStatusCode());
            String responseBody3 = IOUtils.toString(tokenResponse3.getEntity().getContent(), StandardCharsets.UTF_8);

            List<AuthorizationDetailResponse> authDetailsResponse3 = parseAuthorizationDetails(responseBody3);
            assertEquals(1, authDetailsResponse3.size());
            AuthorizationDetailResponse authDetailResponse3 = authDetailsResponse3.get(0);
            assertEquals("vc+sd-jwt", authDetailResponse3.getFormat());
            assertNotNull(authDetailResponse3.getCredentialIdentifiers());
            assertEquals(1, authDetailResponse3.getCredentialIdentifiers().size());
            String formatIdentifier = authDetailResponse3.getCredentialIdentifiers().get(0);

            // Should be different from the credential_configuration_id based identifier
            assertFalse("Format-based identifier should be different from credential_configuration_id based identifier",
                    firstIdentifier.equals(formatIdentifier));
            assertTrue("Format-based identifier should start with format", formatIdentifier.startsWith("vc+sd-jwt-"));
        }
    }

    @Test
    public void testCredentialIdentifierDifferentSessions() throws Exception {
        // Test that different sessions generate different identifiers for the same credential_configuration_id

        // 1. First session - get a token and make a request
        String token1 = getBearerToken(oauth);

        // Prepare authorization_details with credential_configuration_id
        AuthorizationDetail authDetail = new AuthorizationDetail();
        authDetail.setType("openid_credential");
        authDetail.setCredentialConfigurationId("test-credential");
        List<AuthorizationDetail> authDetails = List.of(authDetail);
        String authDetailsJson = JsonSerialization.writeValueAsString(authDetails);

        // Get credential offer URI for first session
        HttpGet getCredentialOfferURI1 = new HttpGet(getBasePath(TEST_REALM_NAME) + "credential-offer-uri?credential_configuration_id=test-credential");
        getCredentialOfferURI1.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token1);
        CredentialOfferURI credentialOfferURI1;
        try (CloseableHttpResponse response = httpClient.execute(getCredentialOfferURI1)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            credentialOfferURI1 = JsonSerialization.readValue(s, CredentialOfferURI.class);
        }

        // Get credential offer for first session
        HttpGet getCredentialOffer1 = new HttpGet(credentialOfferURI1.getIssuer() + "/" + credentialOfferURI1.getNonce());
        CredentialsOffer credentialsOffer1;
        try (CloseableHttpResponse response = httpClient.execute(getCredentialOffer1)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            credentialsOffer1 = JsonSerialization.readValue(s, CredentialsOffer.class);
        }

        // Get issuer metadata and openid configuration
        HttpGet getIssuerMetadata = new HttpGet(credentialsOffer1.getCredentialIssuer() + "/.well-known/openid-credential-issuer");
        CredentialIssuer credentialIssuer;
        try (CloseableHttpResponse response = httpClient.execute(getIssuerMetadata)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            credentialIssuer = JsonSerialization.readValue(s, CredentialIssuer.class);
        }

        HttpGet getOpenidConfiguration = new HttpGet(credentialIssuer.getAuthorizationServers().get(0) + "/.well-known/openid-configuration");
        OIDCConfigurationRepresentation openidConfig;
        try (CloseableHttpResponse response = httpClient.execute(getOpenidConfiguration)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            openidConfig = JsonSerialization.readValue(s, OIDCConfigurationRepresentation.class);
        }

        // Make token request for first session
        HttpPost postPreAuthorizedCode1 = new HttpPost(openidConfig.getTokenEndpoint());
        List<NameValuePair> parameters1 = new LinkedList<>();
        parameters1.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, PreAuthorizedCodeGrantTypeFactory.GRANT_TYPE));
        parameters1.add(new BasicNameValuePair(PreAuthorizedCodeGrantTypeFactory.CODE_REQUEST_PARAM, credentialsOffer1.getGrants().getPreAuthorizedCode().getPreAuthorizedCode()));
        parameters1.add(new BasicNameValuePair("authorization_details", authDetailsJson));
        UrlEncodedFormEntity formEntity1 = new UrlEncodedFormEntity(parameters1, StandardCharsets.UTF_8);
        postPreAuthorizedCode1.setEntity(formEntity1);

        String firstSessionIdentifier = null;
        try (CloseableHttpResponse tokenResponse1 = httpClient.execute(postPreAuthorizedCode1)) {
            assertEquals(HttpStatus.SC_OK, tokenResponse1.getStatusLine().getStatusCode());
            String responseBody1 = IOUtils.toString(tokenResponse1.getEntity().getContent(), StandardCharsets.UTF_8);

            List<AuthorizationDetailResponse> authDetailsResponse1 = parseAuthorizationDetails(responseBody1);
            assertEquals(1, authDetailsResponse1.size());
            AuthorizationDetailResponse authDetailResponse1 = authDetailsResponse1.get(0);
            assertEquals("test-credential", authDetailResponse1.getCredentialConfigurationId());
            assertNotNull(authDetailResponse1.getCredentialIdentifiers());
            assertEquals(1, authDetailResponse1.getCredentialIdentifiers().size());
            firstSessionIdentifier = authDetailResponse1.getCredentialIdentifiers().get(0);
            assertTrue("Identifier should start with credential_configuration_id", firstSessionIdentifier.startsWith("test-credential-"));
        }

        // 2. Second session - get a new token and make a request
        // Clear cookies to ensure a new session
        deleteAllCookiesForRealm(TEST_REALM_NAME);
        String token2 = getBearerToken(oauth);

        // Get credential offer URI for second session
        HttpGet getCredentialOfferURI2 = new HttpGet(getBasePath(TEST_REALM_NAME) + "credential-offer-uri?credential_configuration_id=test-credential");
        getCredentialOfferURI2.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token2);
        CredentialOfferURI credentialOfferURI2;
        try (CloseableHttpResponse response = httpClient.execute(getCredentialOfferURI2)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            credentialOfferURI2 = JsonSerialization.readValue(s, CredentialOfferURI.class);
        }

        // Get credential offer for second session
        HttpGet getCredentialOffer2 = new HttpGet(credentialOfferURI2.getIssuer() + "/" + credentialOfferURI2.getNonce());
        CredentialsOffer credentialsOffer2;
        try (CloseableHttpResponse response = httpClient.execute(getCredentialOffer2)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            credentialsOffer2 = JsonSerialization.readValue(s, CredentialsOffer.class);
        }

        // Make token request for second session
        HttpPost postPreAuthorizedCode2 = new HttpPost(openidConfig.getTokenEndpoint());
        List<NameValuePair> parameters2 = new LinkedList<>();
        parameters2.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, PreAuthorizedCodeGrantTypeFactory.GRANT_TYPE));
        parameters2.add(new BasicNameValuePair(PreAuthorizedCodeGrantTypeFactory.CODE_REQUEST_PARAM, credentialsOffer2.getGrants().getPreAuthorizedCode().getPreAuthorizedCode()));
        parameters2.add(new BasicNameValuePair("authorization_details", authDetailsJson));
        UrlEncodedFormEntity formEntity2 = new UrlEncodedFormEntity(parameters2, StandardCharsets.UTF_8);
        postPreAuthorizedCode2.setEntity(formEntity2);

        try (CloseableHttpResponse tokenResponse2 = httpClient.execute(postPreAuthorizedCode2)) {
            assertEquals(HttpStatus.SC_OK, tokenResponse2.getStatusLine().getStatusCode());
            String responseBody2 = IOUtils.toString(tokenResponse2.getEntity().getContent(), StandardCharsets.UTF_8);

            List<AuthorizationDetailResponse> authDetailsResponse2 = parseAuthorizationDetails(responseBody2);
            assertEquals(1, authDetailsResponse2.size());
            AuthorizationDetailResponse authDetailResponse2 = authDetailsResponse2.get(0);
            assertEquals("test-credential", authDetailResponse2.getCredentialConfigurationId());
            assertNotNull(authDetailResponse2.getCredentialIdentifiers());
            assertEquals(1, authDetailResponse2.getCredentialIdentifiers().size());
            String secondSessionIdentifier = authDetailResponse2.getCredentialIdentifiers().get(0);

            // Should be different from the first session identifier
            assertFalse("Different sessions should generate different identifiers for the same credential_configuration_id",
                    firstSessionIdentifier.equals(secondSessionIdentifier));
            assertTrue("Second session identifier should start with credential_configuration_id",
                    secondSessionIdentifier.startsWith("test-credential-"));
        }
    }
}
