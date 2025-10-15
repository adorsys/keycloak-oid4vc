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

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.core.Response;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicNameValuePair;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.protocol.oid4vc.issuance.OID4VCAuthorizationDetailsProcessor;
import org.keycloak.protocol.oid4vc.model.AuthorizationDetail;
import org.keycloak.protocol.oid4vc.model.CredentialIssuer;
import org.keycloak.protocol.oid4vc.model.CredentialOfferURI;
import org.keycloak.protocol.oid4vc.model.CredentialRequest;
import org.keycloak.protocol.oid4vc.model.CredentialResponse;
import org.keycloak.protocol.oid4vc.model.CredentialsOffer;
import org.keycloak.protocol.oidc.grants.PreAuthorizedCodeGrantTypeFactory;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.arquillian.annotation.EnableFeature;
import org.keycloak.testsuite.util.AdminClientUtil;
import org.keycloak.testsuite.util.oauth.OAuthClient;
import org.keycloak.common.Profile;
import org.keycloak.util.JsonSerialization;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import static org.junit.Assert.*;
import static org.keycloak.protocol.oid4vc.issuance.OID4VCAuthorizationDetailsProcessor.OPENID_CREDENTIAL_TYPE;

/**
 * Test to verify that authorization_details_types_supported is included in the OAuth Authorization Server
 * metadata endpoint (/.well-known/oauth-authorization-server/) and that credential issuance works with
 * authorization_details when scope is absent.
 */
@EnableFeature(value = Profile.Feature.OID4VC_VCI, skipRestart = true)
public class OID4VCAuthorizationDetailsTypesSupportedTest extends OID4VCIssuerEndpointTest {

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
        super.configureTestRealm(testRealm);

        testRealm.setVerifiableCredentialsEnabled(true);
    }

    @Test
    public void testAuthorizationDetailsTypesSupportedInOAuthAuthorizationServerMetadata() {
        try (Client client = AdminClientUtil.createResteasyClient()) {
            // Get OAuth Authorization Server metadata as required by OID4VC spec
            OIDCConfigurationRepresentation oauthConfig = getOAuth2WellKnownConfiguration(client);

            // Verify that authorization_details_types_supported is present
            assertNotNull("authorization_details_types_supported should be present",
                    oauthConfig.getAuthorizationDetailsTypesSupported());

            // Verify that it contains openid_credential
            List<String> supportedTypes = oauthConfig.getAuthorizationDetailsTypesSupported();
            assertTrue("authorization_details_types_supported should contain openid_credential",
                    supportedTypes.contains(OID4VCAuthorizationDetailsProcessor.OPENID_CREDENTIAL_TYPE));

            // Verify it contains exactly one type
            assertEquals("authorization_details_types_supported should contain exactly one type",
                    1, supportedTypes.size());

        }
    }

    @Test
    public void testCredentialIssuanceWithAuthorizationDetails() throws Exception {

        try (Client client = AdminClientUtil.createResteasyClient()) {
            // Verify OAuth2 well-known endpoint includes authorization_details_types_supported
            OIDCConfigurationRepresentation oauth2Config = getOAuth2WellKnownConfiguration(client);
            assertNotNull("authorization_details_types_supported should be present",
                    oauth2Config.getAuthorizationDetailsTypesSupported());
            assertTrue("authorization_details_types_supported should contain openid_credential",
                    oauth2Config.getAuthorizationDetailsTypesSupported().contains(OPENID_CREDENTIAL_TYPE));

            // Get credential issuer metadata
            CredentialIssuer credentialIssuer = getCredentialIssuerMetadata(client);
            assertNotNull("Credential issuer should not be null", credentialIssuer);
            assertNotNull("Authorization servers should be present", credentialIssuer.getAuthorizationServers());
            assertFalse("Authorization servers should not be empty", credentialIssuer.getAuthorizationServers().isEmpty());

            // Verify the authorization server from credential issuer metadata
            String authServerUri = credentialIssuer.getAuthorizationServers().get(0);
            OIDCConfigurationRepresentation authServerConfig = getOAuth2WellKnownConfigurationFromUri(client, authServerUri);
            assertNotNull("Authorization server should support authorization_details_types_supported",
                    authServerConfig.getAuthorizationDetailsTypesSupported());
            assertTrue("Authorization server should support openid_credential",
                    authServerConfig.getAuthorizationDetailsTypesSupported().contains(OPENID_CREDENTIAL_TYPE));

            // Create a credential offer to test the complete flow
            CredentialsOffer credentialsOffer = createCredentialOffer(credentialIssuer);
            assertNotNull("Credential offer should be created", credentialsOffer);
            assertNotNull("Pre-authorized code should be present",
                    credentialsOffer.getGrants().getPreAuthorizedCode().getPreAuthorizedCode());

            // Test token exchange with authorization_details
            String accessToken = exchangePreAuthorizedCodeForTokenWithAuthorizationDetails(
                    authServerConfig, credentialsOffer, credentialIssuer);
            assertNotNull("Access token should be obtained", accessToken);

            // Test credential request with the access token
            CredentialResponse credentialResponse = requestCredentialWithToken(
                    credentialIssuer, accessToken);
            assertNotNull("Credential response should be obtained", credentialResponse);
            assertNotNull("Credentials should be present in response", credentialResponse.getCredentials());
            assertFalse("Credentials should not be empty", credentialResponse.getCredentials().isEmpty());
        }
    }

    @Test
    public void testAuthorizationDetailsTypesSupportedNotInOAuth2WellKnownWhenOID4VCDisabled() {
        // Disable OID4VC for this realm
        RealmRepresentation realmRep = adminClient.realm("test").toRepresentation();
        realmRep.setVerifiableCredentialsEnabled(false);
        adminClient.realm("test").update(realmRep);

        try (Client client = AdminClientUtil.createResteasyClient()) {
            // Get OAuth2 well-known configuration
            OIDCConfigurationRepresentation oauth2Config = getOAuth2WellKnownConfiguration(client);

            // Verify that authorization_details_types_supported is not present
            assertNull("authorization_details_types_supported should not be present when OID4VC is disabled",
                    oauth2Config.getAuthorizationDetailsTypesSupported());

        } finally {
            // Re-enable OID4VC for cleanup
            realmRep.setVerifiableCredentialsEnabled(true);
            adminClient.realm("test").update(realmRep);
        }
    }

    private OIDCConfigurationRepresentation getOAuth2WellKnownConfiguration(Client client) {
        String oauth2WellKnownUri = OAuthClient.AUTH_SERVER_ROOT + "/.well-known/oauth-authorization-server/realms/test";

        Response response = client.target(oauth2WellKnownUri)
                .request()
                .get();

        assertEquals("OAuth Authorization Server metadata endpoint should return 200", 200, response.getStatus());

        return response.readEntity(OIDCConfigurationRepresentation.class);
    }

    private OIDCConfigurationRepresentation getOAuth2WellKnownConfigurationFromUri(Client client, String authServerUri) {
        String oauth2WellKnownUri = authServerUri + "/.well-known/oauth-authorization-server";

        Response response = client.target(oauth2WellKnownUri)
                .request()
                .get();

        assertEquals("OAuth Authorization Server metadata endpoint should return 200", 200, response.getStatus());

        return response.readEntity(OIDCConfigurationRepresentation.class);
    }

    private CredentialIssuer getCredentialIssuerMetadata(Client client) {
        String credentialIssuerUri = OAuthClient.AUTH_SERVER_ROOT + "/realms/test/.well-known/openid-credential-issuer";

        Response response = client.target(credentialIssuerUri)
                .request()
                .get();

        assertEquals("Credential issuer endpoint should return 200", 200, response.getStatus());

        return response.readEntity(CredentialIssuer.class);
    }

    private CredentialsOffer createCredentialOffer(CredentialIssuer credentialIssuer) throws Exception {
        String token = getBearerToken(oauth);

        // Create credential offer URI using the proper base path
        HttpGet getCredentialOfferURI = new HttpGet(getBasePath(TEST_REALM_NAME) + "credential-offer-uri?credential_configuration_id=" + jwtTypeCredentialConfigurationIdName);
        getCredentialOfferURI.addHeader("Authorization", "Bearer " + token);

        CredentialOfferURI credentialOfferURI;
        try (CloseableHttpResponse response = httpClient.execute(getCredentialOfferURI)) {
            assertEquals("Credential offer URI should be created", HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String responseBody = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            credentialOfferURI = JsonSerialization.readValue(responseBody, CredentialOfferURI.class);
        }

        // Get the actual credential offer
        HttpGet getCredentialOffer = new HttpGet(credentialOfferURI.getIssuer() + "/" + credentialOfferURI.getNonce());
        try (CloseableHttpResponse response = httpClient.execute(getCredentialOffer)) {
            assertEquals("Credential offer should be retrieved", HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String responseBody = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            return JsonSerialization.readValue(responseBody, CredentialsOffer.class);
        }
    }

    private String exchangePreAuthorizedCodeForTokenWithAuthorizationDetails(
            OIDCConfigurationRepresentation oauth2Config, CredentialsOffer credentialsOffer,
            CredentialIssuer credentialIssuer) throws Exception {

        // Create authorization details for openid_credential
        AuthorizationDetail authDetail = new AuthorizationDetail();
        authDetail.setType(OPENID_CREDENTIAL_TYPE);
        authDetail.setCredentialConfigurationId(jwtTypeCredentialConfigurationIdName);
        authDetail.setLocations(Collections.singletonList(credentialIssuer.getCredentialIssuer()));

        List<AuthorizationDetail> authDetails = List.of(authDetail);
        String authDetailsJson = JsonSerialization.writeValueAsString(authDetails);

        // Exchange pre-authorized code for token with authorization_details
        HttpPost postToken = new HttpPost(oauth2Config.getTokenEndpoint());
        List<NameValuePair> parameters = new LinkedList<>();
        parameters.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, PreAuthorizedCodeGrantTypeFactory.GRANT_TYPE));
        parameters.add(new BasicNameValuePair(PreAuthorizedCodeGrantTypeFactory.CODE_REQUEST_PARAM,
                credentialsOffer.getGrants().getPreAuthorizedCode().getPreAuthorizedCode()));
        parameters.add(new BasicNameValuePair("authorization_details", authDetailsJson));

        UrlEncodedFormEntity formEntity = new UrlEncodedFormEntity(parameters, StandardCharsets.UTF_8);
        postToken.setEntity(formEntity);

        try (CloseableHttpResponse response = httpClient.execute(postToken)) {
            assertEquals("Token exchange should succeed", HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String responseBody = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            return JsonSerialization.readValue(responseBody, org.keycloak.representations.AccessTokenResponse.class).getToken();
        }
    }

    private CredentialResponse requestCredentialWithToken(CredentialIssuer credentialIssuer, String accessToken) throws Exception {
        // Create credential request
        CredentialRequest credentialRequest = new CredentialRequest();
        credentialRequest.setCredentialIdentifier(jwtTypeCredentialScopeName);
        credentialRequest.setCredentialConfigurationId(jwtTypeCredentialConfigurationIdName);

        String credentialRequestJson = JsonSerialization.writeValueAsString(credentialRequest);

        // Request credential with access token
        HttpPost postCredential = new HttpPost(credentialIssuer.getCredentialEndpoint());
        postCredential.addHeader("Authorization", "Bearer " + accessToken);
        postCredential.addHeader("Content-Type", "application/json");
        postCredential.setEntity(new StringEntity(credentialRequestJson, StandardCharsets.UTF_8));

        try (CloseableHttpResponse response = httpClient.execute(postCredential)) {
            assertEquals("Credential request should succeed", HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String responseBody = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
            return JsonSerialization.readValue(responseBody, CredentialResponse.class);
        }
    }

}
