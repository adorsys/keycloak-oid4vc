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

package org.keycloak.testsuite.oid4vc.oid4vp;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.Profile;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthenticationEndpointFactory;
import org.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import org.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import org.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import org.keycloak.testsuite.arquillian.annotation.EnableFeature;
import org.keycloak.testsuite.oid4vc.issuance.signing.OID4VCIssuerEndpointTest;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthenticationEndpointBase.pruneAuthSessionId;

/**
 * Testing OpenID4VP user authentication via presentation of SD-JWT identity credentials.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
@EnableFeature(value = Profile.Feature.OID4VC_VPAUTH, skipRestart = true)
public class OID4VPUserAuthenticationEndpointTest extends OID4VCIssuerEndpointTest {

    protected static final String TEST_USER = "test-user@localhost";
    protected static final String TEST_CLIENT_ID = "test-app";
    protected static final String TEST_CLIENT_SECRET = "password";

    @Test
    public void shouldProduceAuthorizationRequests() throws Exception {
        AuthorizationContext authContext = requestAuthorizationRequest();

        // Assert: These fields must be present.
        assertNotNull(authContext.getAuthorizationRequest());
        assertNotNull(authContext.getTransactionId());

        // The authorization request must be a valid URL of scheme "openid4vp".
        URI authRequest = new URI(authContext.getAuthorizationRequest());
        assertEquals("openid4vp", authRequest.getScheme());
    }

    @Test
    public void shouldResolveRequestURIs() throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        String authRequest = authContext.getAuthorizationRequest();

        // Resolve the request_uri parameter from the authorization request
        RequestObject requestObject = resolveRequestObject(authRequest);

        // Assert: Ensure authentication sessions match
        String expectedSessionId = pruneAuthSessionId(authContext.getTransactionId());
        String actualSessionId = pruneAuthSessionId(requestObject.getState());
        assertEquals(expectedSessionId, actualSessionId);
    }

    @Test
    public void shouldEnableStatusPolling() throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        String transactionId = authContext.getTransactionId();

        // Poll the status of the authorization context
        String url = getOid4vpEndpoint(String.format("/status/%s", transactionId));
        HttpGet httpGet = new HttpGet(url);
        HttpResponse response = httpClient.execute(httpGet);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Parse response
        AuthorizationContext statusPayload = JsonSerialization.readValue(
                EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8),
                AuthorizationContext.class
        );

        // Assert
        assertEquals(AuthorizationContextStatus.PENDING, statusPayload.getStatus());
    }

    @Test
    public void shouldNotDiscloseStatusWithRequestIDs() throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());
        String requestId = requestObject.getState();

        // Poll the status of the authorization context
        String url = getOid4vpEndpoint(String.format("/status/%s", requestId));
        HttpGet httpGet = new HttpGet(url);
        HttpResponse response = httpClient.execute(httpGet);
        assertEquals("Only transaction IDs should enable polling authorization statuses",
                HttpStatus.SC_NOT_FOUND, response.getStatusLine().getStatusCode());
    }

    private AuthorizationContext requestAuthorizationRequest() throws Exception {
        String url = getOid4vpEndpoint("/request");
        List<BasicNameValuePair> params = getClientAuthParams();

        HttpPost httpPost = new HttpPost(url);
        httpPost.setEntity(new UrlEncodedFormEntity(params));
        HttpResponse response = httpClient.execute(httpPost);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        return JsonSerialization.readValue(
                EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8),
                AuthorizationContext.class
        );
    }

    private RequestObject resolveRequestObject(String authRequest) throws IOException, JWSInputException {
        // Extract the request_uri parameter
        String requestUri = URLEncodedUtils.parse(authRequest, StandardCharsets.UTF_8).stream()
                .filter(p -> p.getName().equals("request_uri"))
                .map(NameValuePair::getValue)
                .findFirst()
                .orElseThrow(() -> new AssertionError("Missing query param: request_uri"));

        // Send resolution request
        HttpGet httpGet = new HttpGet(requestUri);
        HttpResponse response = httpClient.execute(httpGet);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Parse and return the expected JWT response
        String signedRequestJwt = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        JWSInput jwsInput = new JWSInput(signedRequestJwt);
        return jwsInput.readJsonContent(RequestObject.class);
    }

    private String getOid4vpEndpoint(String route) {
        return KeycloakUriBuilder.fromUri(getRealmPath(TEST_REALM_NAME))
                .path(OID4VPUserAuthenticationEndpointFactory.PROVIDER_ID)
                .path(route)
                .build()
                .toString();
    }

    private static List<BasicNameValuePair> getClientAuthParams() {
        return new ArrayList<>(List.of(
                new BasicNameValuePair(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID),
                new BasicNameValuePair(OAuth2Constants.CLIENT_SECRET, TEST_CLIENT_SECRET)
        ));
    }
}
