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
package org.keycloak.testsuite.oid4vc.issuance;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.core.Response;
import org.apache.http.HttpStatus;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.constants.Oid4VciConstants;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerEndpoint;
import org.keycloak.protocol.oid4vc.model.CredentialRequest;
import org.keycloak.protocol.oid4vc.model.CredentialResponse;
import org.keycloak.protocol.oid4vc.model.DisplayObject;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.oid4vc.issuance.signing.OID4VCIssuerEndpointTest;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiConsumer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Integration test to validate that status.status_list.idx is normalized from string to integer
 * in SD-JWT credentials. This test ensures the fix for conformance test failures.
 * 
 * <p>This test validates normalization for claims added via setClaimsForSubject() (credentialSubject.getClaims()).
 * The normalization logic also handles claims added via setClaimsForCredential() to VerifiableCredential.additionalProperties,
 * which is used by external mappers like StatusListProtocolMapper.</p>
 *
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 */
public class OID4VCStatusListIdxNormalizationTest extends OID4VCIssuerEndpointTest {

    private ClientScopeRepresentation testClientScope;

    @Before
    @Override
    public void setup() {
        super.setup();

        // Create a test client scope with SD-JWT format and status claim visible
        String scopeName = "test-status-list-scope";
        String credentialConfigurationId = "test-status-list-config-id";
        String credentialIdentifier = "test-status-list-scope";
        String vct = "https://credentials.example.com/test-status-credential";
        String format = Format.SD_JWT_VC;

        // Check if the client scope already exists
        List<ClientScopeRepresentation> existingScopes = testRealm().clientScopes().findAll();
        for (ClientScopeRepresentation existingScope : existingScopes) {
            if (existingScope.getName().equals(scopeName)) {
                testClientScope = existingScope;
                return;
            }
        }

        // Create a new ClientScope
        ClientScopeRepresentation clientScope = new ClientScopeRepresentation();
        clientScope.setName(scopeName);
        clientScope.setProtocol(Oid4VciConstants.OID4VC_PROTOCOL);
        Map<String, String> attributes = new HashMap<>(Map.of(
                ClientScopeModel.INCLUDE_IN_TOKEN_SCOPE, "true",
                CredentialScopeModel.EXPIRY_IN_SECONDS, "15"));

        BiConsumer<String, String> addAttribute = (attributeName, value) -> {
            if (value != null) {
                attributes.put(attributeName, value);
            }
        };

        addAttribute.accept(CredentialScopeModel.CONFIGURATION_ID, credentialConfigurationId);
        addAttribute.accept(CredentialScopeModel.CREDENTIAL_IDENTIFIER, credentialIdentifier);
        addAttribute.accept(CredentialScopeModel.FORMAT, format);
        addAttribute.accept(CredentialScopeModel.VCT, Optional.ofNullable(vct).orElse(credentialIdentifier));
        addAttribute.accept(CredentialScopeModel.SD_JWT_VISIBLE_CLAIMS, "id,iat,nbf,exp,jti,status");

        if (credentialConfigurationId != null) {
            String vcDisplay;
            try {
                vcDisplay = JsonSerialization.writeValueAsString(List.of(
                        new DisplayObject().setName(credentialConfigurationId).setLocale("en-EN"),
                        new DisplayObject().setName(credentialConfigurationId).setLocale("de-DE")));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            addAttribute.accept(CredentialScopeModel.VC_DISPLAY, vcDisplay);
        }
        clientScope.setAttributes(attributes);

        Response res = testRealm().clientScopes().create(clientScope);
        String scopeId = ApiUtil.getCreatedId(res);
        getCleanup().addClientScopeId(scopeId);
        res.close();

        clientScope.setId(scopeId);

        // Get default protocol mappers and add status mapper with idx as string
        // Create a mutable copy since getProtocolMappers() returns an immutable List
        List<ProtocolMapperRepresentation> protocolMappers = new ArrayList<>(getProtocolMappers(scopeName));

        // Add a static claim mapper to add status with idx as string (simulating real mapper behavior)
        // The normalization should convert it to integer
        ProtocolMapperRepresentation statusMapper = new ProtocolMapperRepresentation();
        statusMapper.setName("status-list-mapper");
        statusMapper.setProtocol(Oid4VciConstants.OID4VC_PROTOCOL);
        statusMapper.setProtocolMapper("oid4vc-static-claim-mapper");
        Map<String, String> config = new HashMap<>();
        config.put("claim.name", "status");
        // JSON string will be parsed by OID4VCStaticClaimMapper and normalized by SdJwtCredentialBuilder
        config.put("staticValue", "{\"status_list\":{\"idx\":\"0\",\"uri\":\"test-status-list-uri\"}}");
        statusMapper.setConfig(config);
        protocolMappers.add(statusMapper);

        // Add protocol mappers to the client scope
        addProtocolMappersToClientScope(clientScope, protocolMappers);
        clientScope.setProtocolMappers(protocolMappers);

        testClientScope = clientScope;

        // Assign the scope to the client
        ClientResource clientResource = findClientByClientId(testRealm(), client.getClientId());
        clientResource.addOptionalClientScope(scopeId);
    }

    private ClientResource findClientByClientId(RealmResource realm, String clientId) {
        for (ClientRepresentation c : realm.clients().findAll()) {
            if (clientId.equals(c.getClientId())) {
                return realm.clients().get(c.getId());
            }
        }
        return null;
    }

    @Test
    public void testStatusListIdxIsIntegerInCredential() throws Exception {
        // This test validates that status.status_list.idx is normalized from string to integer
        // This is critical for OID4VC conformance tests
        String token = getBearerToken(oauth, client, testClientScope.getName());

        // Extract values before lambda to avoid serialization issues
        String credentialConfigurationId = testClientScope.getAttributes()
                .get(CredentialScopeModel.CONFIGURATION_ID);

        testingClient.server(TEST_REALM_NAME).run(session -> {
            AppAuthManager.BearerTokenAuthenticator authenticator = new AppAuthManager.BearerTokenAuthenticator(session);
            authenticator.setTokenString(token);
            OID4VCIssuerEndpoint issuerEndpoint = prepareIssuerEndpoint(session, authenticator);

            // Create a credential request
            CredentialRequest credentialRequest = new CredentialRequest()
                    .setCredentialConfigurationId(credentialConfigurationId);

            String requestPayload = JsonSerialization.writeValueAsString(credentialRequest);

            // Request the credential
            Response credentialResponse = issuerEndpoint.requestCredential(requestPayload);
            assertEquals("The credential request should be answered successfully.",
                    HttpStatus.SC_OK, credentialResponse.getStatus());

            assertNotNull("A credential should be responded.", credentialResponse.getEntity());

            CredentialResponse credentialResponseVO = JsonSerialization.mapper
                    .convertValue(credentialResponse.getEntity(), CredentialResponse.class);

            String credentialString = (String) credentialResponseVO.getCredentials().get(0).getCredential();
            assertNotNull("A valid credential string should have been responded", credentialString);

            // Parse the SD-JWT credential
            SdJwtVP sdJwtVP = SdJwtVP.of(credentialString);
            assertNotNull("The SD-JWT should be parseable", sdJwtVP);

            IssuerSignedJWT jwt = sdJwtVP.getIssuerSignedJWT();
            assertNotNull("The issuer signed JWT should be present", jwt);

            // Assert status claim exists and verify idx is normalized to integer
            JsonNode statusClaim = jwt.getPayload().get("status");
            assertNotNull("status claim must be present in the credential", statusClaim);
            assertTrue("status claim must have status_list", statusClaim.has("status_list"));

            JsonNode statusListClaim = statusClaim.get("status_list");
            assertNotNull("status_list claim must be present", statusListClaim);
            assertTrue("status_list must have idx field", statusListClaim.has("idx"));

            JsonNode idxClaim = statusListClaim.get("idx");
            assertNotNull("idx claim must be present", idxClaim);

            // CRITICAL ASSERTION: idx MUST be an integer, not a string
            assertTrue("idx must be a number (integer), not a string. " +
                            "This is required by the OID4VC specification. " +
                            "Current value: " + idxClaim.toString() + " (type: " + idxClaim.getNodeType() + "). " +
                            "The conformance test will fail with: 'getInt called on something that is not a number'",
                    idxClaim.isNumber());

            // Verify we can read it as an integer without exceptions
            int idxValue = idxClaim.asInt();
            assertTrue("idx should be a non-negative integer", idxValue >= 0);
            assertEquals("idx should be 0", 0, idxValue);
        });
    }
}
