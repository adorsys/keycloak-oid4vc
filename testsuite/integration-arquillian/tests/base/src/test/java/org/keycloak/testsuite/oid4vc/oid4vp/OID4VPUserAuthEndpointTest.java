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

import jakarta.ws.rs.core.Response;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.TokenVerifier;
import org.keycloak.common.Profile;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.keys.Attributes;
import org.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointFactory;
import org.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory;
import org.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import org.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import org.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import org.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import org.keycloak.protocol.oid4vc.oid4vp.model.dto.ProcessingError;
import org.keycloak.protocol.oid4vc.oid4vp.model.prex.Descriptor;
import org.keycloak.protocol.oid4vc.oid4vp.model.prex.InputDescriptor;
import org.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationDefinition;
import org.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationSubmission;
import org.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationResponseService;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.representations.idm.ComponentExportRepresentation;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.testsuite.arquillian.annotation.EnableFeature;
import org.keycloak.testsuite.oid4vc.issuance.signing.OID4VCIssuerEndpointTest;
import org.keycloak.testsuite.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.keycloak.models.utils.DefaultAuthenticationFlows.OID4VP_AUTH_FLOW;
import static org.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint.REQUEST_JWT_PATH;
import static org.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase.pruneAuthSessionId;
import static org.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.VCT_CONFIG_DEFAULT;

/**
 * Testing OpenID4VP user authentication via presentation of SD-JWT identity credentials.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
@EnableFeature(value = Profile.Feature.OID4VC_VPAUTH, skipRestart = true)
public class OID4VPUserAuthEndpointTest extends OID4VCIssuerEndpointTest {

    private static final String TEST_USER = "test-user@localhost";
    private static final String TEST_CLIENT_ID = "test-app";
    private static final String TEST_CLIENT_SECRET = "password";
    private static final String SD_JWT_AUTH_CONFIG = "sd-jwt-auth-config";

    private SdJwtVPTestUtils sdJwtVPTestUtils;

    @Before
    public void init() {
        // Initialize SD-JWT manipulation utils
        sdJwtVPTestUtils = new SdJwtVPTestUtils(testingClient);

        // Create authenticator config that enforces exp claim validation
        AuthenticatorConfigRepresentation authConfig = new AuthenticatorConfigRepresentation();
        authConfig.setAlias(SD_JWT_AUTH_CONFIG);
        authConfig.setConfig(Map.of(SdJwtAuthenticatorFactory.ENFORCE_EXP_CLAIM_CONFIG, "true"));

        // Register the authenticator config
        var execution = testRealm().flows().getExecutions(OID4VP_AUTH_FLOW).get(0);
        try (Response resp = testRealm().flows().newExecutionConfig(execution.getId(), authConfig)) {
            assertEquals(HttpStatus.SC_CREATED, resp.getStatus());
        }
    }

    @Override
    protected ComponentExportRepresentation getKeyProvider() {
        ComponentExportRepresentation rep = super.getEcKeyProvider();
        rep.getConfig().add(Attributes.EC_GENERATE_CERTIFICATE_KEY, "true");
        return rep;
    }

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
    public void shouldNotResolveUnknownRequestURIs() throws Exception {
        String requestUri = getOid4vpEndpoint(REQUEST_JWT_PATH + "/unknown-request-uri");
        HttpGet httpGet = new HttpGet(requestUri);
        HttpResponse response = httpClient.execute(httpGet);
        assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusLine().getStatusCode());

        OAuth2ErrorRepresentation errorRep = parseErrorResponse(response);
        assertEquals("Authorization context not found for request ID: unknown-request-uri",
                errorRep.getErrorDescription());
    }

    @Test
    public void shouldEnableStatusPolling() throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        String transactionId = authContext.getTransactionId();

        // Poll the status of the authorization context
        HttpResponse response = fetchAuthenticationStatus(transactionId);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Parse response and assert status
        AuthorizationContext statusPayload = parseAuthorizationContext(response);
        assertEquals(AuthorizationContextStatus.PENDING, statusPayload.getStatus());
    }

    @Test
    public void shouldNotDiscloseStatusWithRequestIDs() throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());
        String requestId = requestObject.getState();

        // Poll the status of the authorization context
        HttpResponse response = fetchAuthenticationStatus(requestId);
        assertEquals("Only transaction IDs should enable polling authorization statuses",
                HttpStatus.SC_NOT_FOUND, response.getStatusLine().getStatusCode());
    }

    @Test
    public void shouldAuthenticateSuccessfully_SdJwtWithKid() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Proceed to authentication
        testSuccessfulAuthentication(sdJwt, TestOpts.getDefault());
    }

    @Test
    public void shouldAuthenticateSuccessfully_SdJwtWithoutKid() throws Exception {
        // Request a valid SD-JWT credential from Keycloak without explicit kid
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER, false);

        // Proceed to authentication
        testSuccessfulAuthentication(sdJwt, TestOpts.getDefault());
    }

    @Test
    public void shouldAuthenticateSuccessfully_Base64EncodedVpToken() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Proceed to authentication (Base64-encoded VP token)
        TestOpts opts = TestOpts.getDefault().setShouldBase64EncodeVpToken(true);
        testSuccessfulAuthentication(sdJwt, opts);
    }

    @Test
    public void shouldFailAuthentication_IfRepeatedAfterSuccess() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());

        // Prepare and send the OpenID4VP response to Keycloak
        HttpResponse response = sendAuthorizationResponse(sdJwt, requestObject, TestOpts.getDefault());
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Repeat to failure as expected
        response = sendAuthorizationResponse(sdJwt, requestObject, TestOpts.getDefault());
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusLine().getStatusCode());

        // Assert error response
        OAuth2ErrorRepresentation errorRep = parseErrorResponse(response);
        assertEquals("Authorization context is already closed. Cannot process further responses",
                errorRep.getErrorDescription());
    }

    @Test
    public void shouldFailAuthentication_IfUnknownSessionAssociated() throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());

        // Associate with an unknown session ID
        requestObject.setState("unknown-session-id");

        // Prepare and send the OpenID4VP response to Keycloak
        HttpResponse response = sendAuthorizationResponseWithVPToken(
                "sd-jwt-vptoken", requestObject, TestOpts.getDefault());
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusLine().getStatusCode());

        // Assert error response
        OAuth2ErrorRepresentation errorRep = parseErrorResponse(response);
        assertEquals("Authorization context not found for state (request ID): unknown-session-id",
                errorRep.getErrorDescription());
    }

    @Test
    public void shouldFailAuthentication_InvalidSdJwtVPToken_Empty() throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());

        // Prepare and send the OpenID4VP response to Keycloak
        HttpResponse response = sendAuthorizationResponseWithVPToken(
                "", // This token is invalid because empty
                requestObject,
                new TestOpts()
        );
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusLine().getStatusCode());

        // Assert error response
        OAuth2ErrorRepresentation errorRep = parseErrorResponse(response);
        assertEquals("Unparseable response params (vp_token must not be null or blank)",
                errorRep.getErrorDescription());
    }

    @Test
    public void shouldFailAuthentication_NonMatchingPresentationDefinitionId() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Use a non-matching presentation definition ID
        TestOpts opts = TestOpts.getDefault()
                .setOverridePresentationDefinitionId("unknown-presentation-definition-id");

        testFailingAuthentication(
                sdJwt, opts,
                HttpStatus.SC_BAD_REQUEST,
                ProcessingError.INVALID_PRESENTATION_SUBMISSION.getErrorString(),
                "Presentation submission does not match the expected presentation definition"
        );
    }

    @Test
    public void shouldFailAuthentication_UnsupportedSubmissionDescriptorPath() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Only the root ($) path is supported
        TestOpts opts = TestOpts.getDefault().setOverrideDescriptorPath("$[0]");

        testFailingAuthentication(
                sdJwt, opts,
                HttpStatus.SC_BAD_REQUEST,
                ProcessingError.INVALID_PRESENTATION_SUBMISSION.getErrorString(),
                "Invalid path in presentation submission descriptor: $[0]"
        );
    }

    @Test
    public void shouldFailAuthentication_UnsupportedSubmissionFormat() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Only VC_SD_JWT is supported
        TestOpts opts = TestOpts.getDefault().setOverrideDescriptorFormat(Descriptor.Format.JWT_VP);

        testFailingAuthentication(
                sdJwt, opts,
                HttpStatus.SC_BAD_REQUEST,
                ProcessingError.INVALID_PRESENTATION_SUBMISSION.getErrorString(),
                "SD-JWT VP token expected, but received: jwt_vp"
        );
    }

    @Test
    public void shouldFailAuthentication_InvalidSdJwtVPToken_Unparseable() throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());

        testFailingAuthenticationWithVPToken(
                "a.b.c", // This token is invalid because unparseable as an SD-JWT VP token
                requestObject,
                authContext.getTransactionId(),
                HttpStatus.SC_BAD_REQUEST,
                ProcessingError.INVALID_VP_TOKEN.getErrorString(),
                "Could not parse `vp_token` as an SD-JWT VP token"
        );
    }

    @Test
    public void shouldFailAuthentication_UnknownUser() throws Exception {
        // Request a SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, "unknown-user");

        // Proceed to authentication
        testFailingAuthentication(
                sdJwt, TestOpts.getDefault(),
                HttpStatus.SC_UNAUTHORIZED,
                ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                "USER_NOT_FOUND: User with presented SD-JWT unknown"
        );
    }

    @Test
    public void shouldFailAuthentication_SdJwtWithUnexpectedVct() throws Exception {
        // Request SD-JWT credentials from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential("https://this-vct-is-not-expected.com", TEST_USER);

        // Proceed to authentication
        testFailingAuthentication(
                sdJwt, TestOpts.getDefault(),
                HttpStatus.SC_UNAUTHORIZED,
                ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                "Pattern matching failed for required field"
        );
    }

    @Test
    public void shouldFailAuthentication_SdJwtWithNoUsername() throws Exception {
        // Request SD-JWT credentials from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, null);

        // Proceed to authentication
        testFailingAuthentication(
                sdJwt, TestOpts.getDefault(),
                HttpStatus.SC_UNAUTHORIZED,
                ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                "Invalid SD-JWT presentation (A required field was not presented: `username`)"
        );
    }

    @Test
    public void shouldFailAuthentication_InvalidKbJwt_SignedWithUnboundedKey() throws Exception {
        testFailAuthentication_InvalidKbJwt(
                null, null, // Use expected nonce and aud
                SdJwtVPTestUtils.getStrayJwk(), // Use a stray JWK as holder key
                null, // Use default KB-JWT lifespan
                "Key binding JWT invalid"
        );
    }

    @Test
    public void shouldFailAuthentication_InvalidKbJwt_Expired() throws Exception {
        testFailAuthentication_InvalidKbJwt(
                null, null,  // Use expected nonce and aud
                null, // Use expected holder key
                -SdJwtVPTestUtils.KB_JWT_LIFESPAN_SECS, // Use a negative lifespan to expire the KB-JWT
                "Key binding JWT: Invalid `exp` claim"
        );
    }

    @Test
    public void shouldFailAuthentication_InvalidKbJwt_InvalidNonce() throws Exception {
        testFailAuthentication_InvalidKbJwt(
                "invalid-nonce", null,
                null, null,
                "Key binding JWT: Unexpected `nonce` value"
        );
    }

    @Test
    public void shouldFailAuthentication_InvalidKbJwt_InvalidAud() throws Exception {
        testFailAuthentication_InvalidKbJwt(
                null, "invalid-aud",
                null, null,
                "Key binding JWT: Unexpected `aud` value"
        );
    }

    /**
     * Helper for successful flows.
     */
    private void testSuccessfulAuthentication(String sdJwt, TestOpts opts) throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());

        // Prepare and send the OpenID4VP response to Keycloak
        HttpResponse response = sendAuthorizationResponse(sdJwt, requestObject, opts);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Check auth status
        HttpResponse statusResponse = fetchAuthenticationStatus(authContext.getTransactionId());
        AuthorizationContext statusPayload = parseAuthorizationContext(statusResponse);
        assertEquals(AuthorizationContextStatus.SUCCESS, statusPayload.getStatus());

        // Exchange authorization code for access token
        String authCode = statusPayload.getAuthorizationCode();
        assertNotNull("Authorization code should not be null", authCode);
        AccessTokenResponse tokenResponse = oauth.doAccessTokenRequest(authCode);
        AccessToken accessToken = TokenVerifier
                .create(tokenResponse.getAccessToken(), AccessToken.class)
                .getToken();

        // Assert authenticating user
        assertEquals(TEST_USER, accessToken.getPreferredUsername());
    }

    /**
     * Helper for failing flows.
     */
    private void testFailingAuthentication(
            String sdJwt,
            TestOpts opts,
            int httpStatus,
            String expectedError,
            String expectedErrorDescription
    ) throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());
        if (opts.getOverridePresentationDefinitionId() != null) {
            requestObject.getPresentationDefinition().setId(opts.getOverridePresentationDefinitionId());
        }

        // Prepare and send the OpenID4VP response to Keycloak
        HttpResponse response = sendAuthorizationResponse(sdJwt, requestObject, opts);

        // Run assertions
        assertFailingAuthentication(
                response,
                authContext.getTransactionId(),
                httpStatus,
                expectedError,
                expectedErrorDescription
        );
    }

    /**
     * Helper for failing flows (from VP token).
     */
    private void testFailingAuthenticationWithVPToken(
            String sdJwtVpToken,
            RequestObject requestObject,
            String transactionId,
            int httpStatus,
            String expectedError,
            String expectedErrorDescription
    ) throws Exception {
        // Prepare and send the OpenID4VP response to Keycloak
        HttpResponse response = sendAuthorizationResponseWithVPToken(
                sdJwtVpToken,
                requestObject,
                new TestOpts()
        );

        // Run assertions
        assertFailingAuthentication(
                response,
                transactionId,
                httpStatus,
                expectedError,
                expectedErrorDescription
        );
    }

    /**
     * Helper for asserting failing flows.
     */
    private void assertFailingAuthentication(
            HttpResponse postAuthResponse,
            String transactionId,
            int httpStatus,
            String expectedError,
            String expectedErrorDescription
    ) throws Exception {
        assertEquals(httpStatus, postAuthResponse.getStatusLine().getStatusCode());
        OAuth2ErrorRepresentation errorRep = parseErrorResponse(postAuthResponse);
        assertEquals(expectedError, errorRep.getError());
        assertTrue(errorRep.getErrorDescription().contains(expectedErrorDescription));

        // Check and assert auth status
        HttpResponse statusResponse = fetchAuthenticationStatus(transactionId);
        AuthorizationContext statusPayload = parseAuthorizationContext(statusResponse);
        assertEquals(AuthorizationContextStatus.ERROR, statusPayload.getStatus());
        assertEquals(expectedError, statusPayload.getError().getErrorString());
        assertTrue(statusPayload.getErrorDescription().contains(expectedErrorDescription));
    }

    /**
     * Helper for failing flows (Invalid KB-JWTs).
     */
    private void testFailAuthentication_InvalidKbJwt(
            String overrideNonce,
            String overrideAud,
            JWK holderkey,
            Integer kbJwtLifespanSecs,
            String errorMessage
    ) throws Exception {
        // Request a SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());

        // Prepare SD-JWT VP tokens with invalid KB-JWTs
        String sdJwtVpToken = sdJwtVPTestUtils.presentSdJwt(
                sdJwt,
                overrideNonce == null ? requestObject.getNonce() : overrideNonce,
                overrideAud == null ? requestObject.getClientId() : overrideAud,
                holderkey == null ? SdJwtVPTestUtils.getUserJwk() : holderkey,
                kbJwtLifespanSecs == null ? SdJwtVPTestUtils.KB_JWT_LIFESPAN_SECS : kbJwtLifespanSecs
        );

        // Proceed to authentication
        testFailingAuthenticationWithVPToken(
                sdJwtVpToken,
                requestObject,
                authContext.getTransactionId(),
                HttpStatus.SC_UNAUTHORIZED,
                ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                errorMessage
        );
    }

    /**
     * Request a fresh OpenID4VP authorization request from Keycloak.
     * A request is sent to the endpoint for this purpose.
     */
    private AuthorizationContext requestAuthorizationRequest() throws Exception {
        String url = getOid4vpEndpoint("/request");
        List<BasicNameValuePair> params = getClientAuthParams();

        HttpPost httpPost = new HttpPost(url);
        httpPost.setEntity(new UrlEncodedFormEntity(params));
        HttpResponse response = httpClient.execute(httpPost);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        return parseAuthorizationContext(response);
    }

    /**
     * Resolve the request object associated with the authorization request.
     * A request is sent to the request_uri dereferencing endpoint to retrieve the request object.     *
     */
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

    /**
     * Sends an OpenID4VP response to Keycloak, producing an SD-JWT verifiable presentation.
     */
    private HttpResponse sendAuthorizationResponse(String sdJwt, RequestObject requestObject, TestOpts opts)
            throws Exception {
        // Prepare a valid SD-JWT verifiable presentation
        String sdJwtVpToken = sdJwtVPTestUtils.presentSdJwt(
                sdJwt,
                requestObject.getNonce(),
                requestObject.getClientId(),
                SdJwtVPTestUtils.getUserJwk()
        );

        // Base64-encode the SD-JWT VP token if requested
        if (opts.getShouldBase64EncodeVpToken()) {
            byte[] bytes = sdJwtVpToken.getBytes(StandardCharsets.UTF_8);
            sdJwtVpToken = Base64.getUrlEncoder().encodeToString(bytes);
        }

        // Send the OpenID4VP response to Keycloak
        return sendAuthorizationResponseWithVPToken(sdJwtVpToken, requestObject, opts);
    }

    /**
     * Sends an OpenID4VP response to Keycloak, producing an SD-JWT verifiable presentation.
     */
    private HttpResponse sendAuthorizationResponseWithVPToken(
            String sdJwtVpToken,
            RequestObject requestObject,
            TestOpts opts
    ) throws Exception {
        // Wrap the SD-JWT VP in an OpenID4VP response
        List<BasicNameValuePair> oid4vpResponse = prepareOpenID4VPResponse(
                sdJwtVpToken,
                requestObject,
                opts
        );

        // Send the OpenID4VP response to Keycloak
        String url = getOid4vpEndpoint("/response");
        HttpPost httpPost = new HttpPost(url);
        httpPost.setEntity(new UrlEncodedFormEntity(oid4vpResponse));
        return httpClient.execute(httpPost);
    }

    /**
     * Prepare the OpenID4VP response object to be sent to Keycloak.
     *
     * @param sdJwtVpToken  the SD-JWT verifiable presentation token
     * @param requestObject the request object containing the presentation definition
     */
    private List<BasicNameValuePair> prepareOpenID4VPResponse(
            String sdJwtVpToken,
            RequestObject requestObject,
            TestOpts opts
    ) throws IOException {
        // Build presentation submission

        PresentationDefinition definition = requestObject.getPresentationDefinition();
        InputDescriptor inputDescriptor = definition.getInputDescriptors().get(0);

        PresentationSubmission submission = new PresentationSubmission();
        submission.setId(UUID.randomUUID().toString());
        submission.setDefinitionId(definition.getId());

        Descriptor descriptor = new Descriptor();
        descriptor.setId(inputDescriptor.getId());
        descriptor.setFormat(opts.getOverrideDescriptorFormat() == null
                ? Descriptor.Format.VC_SD_JWT
                : opts.getOverrideDescriptorFormat());
        descriptor.setPath(opts.getOverrideDescriptorPath() == null
                ? AuthorizationResponseService.JSON_PATH_ROOT
                : opts.getOverrideDescriptorPath());
        submission.setDescriptorMap(List.of(descriptor));

        // Compose the response object as form-urlencoded parameters

        return new ArrayList<>(List.of(
                new BasicNameValuePair(ResponseObject.VP_TOKEN_KEY, sdJwtVpToken),
                new BasicNameValuePair(ResponseObject.PRESENTATION_SUBMISSION_KEY,
                        JsonSerialization.writeValueAsString(submission)),
                new BasicNameValuePair(ResponseObject.STATE_KEY, requestObject.getState())
        ));
    }

    /**
     * Fetch the authentication status of an opened session by transaction ID.
     */
    private HttpResponse fetchAuthenticationStatus(String transactionId) throws IOException {
        String url = getOid4vpEndpoint(String.format("/status/%s", transactionId));
        HttpGet httpGet = new HttpGet(url);
        return httpClient.execute(httpGet);
    }

    private static AuthorizationContext parseAuthorizationContext(HttpResponse response) throws IOException {
        return JsonSerialization.readValue(
                EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8),
                AuthorizationContext.class
        );
    }

    private static OAuth2ErrorRepresentation parseErrorResponse(HttpResponse response) throws IOException {
        return JsonSerialization.readValue(
                EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8),
                OAuth2ErrorRepresentation.class
        );
    }

    private String getOid4vpEndpoint(String route) {
        return KeycloakUriBuilder.fromUri(getRealmPath(TEST_REALM_NAME))
                .path(OID4VPUserAuthEndpointFactory.PROVIDER_ID)
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

    /**
     * POJO for test options.
     */
    static class TestOpts {

        boolean shouldBase64EncodeVpToken;
        String overridePresentationDefinitionId;
        Descriptor.Format overrideDescriptorFormat;
        String overrideDescriptorPath;

        public static TestOpts getDefault() {
            return new TestOpts();
        }

        public boolean getShouldBase64EncodeVpToken() {
            return shouldBase64EncodeVpToken;
        }

        public TestOpts setShouldBase64EncodeVpToken(boolean shouldBase64EncodeVpToken) {
            this.shouldBase64EncodeVpToken = shouldBase64EncodeVpToken;
            return this;
        }

        public String getOverridePresentationDefinitionId() {
            return overridePresentationDefinitionId;
        }

        public TestOpts setOverridePresentationDefinitionId(String overridePresentationDefinitionId) {
            this.overridePresentationDefinitionId = overridePresentationDefinitionId;
            return this;
        }

        public Descriptor.Format getOverrideDescriptorFormat() {
            return overrideDescriptorFormat;
        }

        public TestOpts setOverrideDescriptorFormat(Descriptor.Format overrideDescriptorFormat) {
            this.overrideDescriptorFormat = overrideDescriptorFormat;
            return this;
        }

        public String getOverrideDescriptorPath() {
            return overrideDescriptorPath;
        }

        public TestOpts setOverrideDescriptorPath(String overrideDescriptorPath) {
            this.overrideDescriptorPath = overrideDescriptorPath;
            return this;
        }
    }
}
