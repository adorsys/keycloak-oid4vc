package org.keycloak.tests.oid4vc.issuance.mappers;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import jakarta.ws.rs.core.Response;

import org.keycloak.TokenVerifier;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientScopeResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.protocol.oid4vc.model.CredentialIssuer;
import org.keycloak.protocol.oid4vc.model.CredentialResponse;
import org.keycloak.protocol.oid4vc.model.OID4VCAuthorizationDetail;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.util.ApiUtil;
import org.keycloak.tests.oid4vc.OID4VCIssuerTestBase;
import org.keycloak.tests.oid4vc.OID4VCTestContext;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.testsuite.util.oauth.AuthorizationEndpointResponse;
import org.keycloak.util.JsonSerialization;

import org.jboss.logging.Logger;
import org.junit.jupiter.api.Test;

import static org.keycloak.OID4VCConstants.OPENID_CREDENTIAL;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@KeycloakIntegrationTest(config = OID4VCIssuerTestBase.VCTestServerConfig.class)
public class OID4VCTargetRoleMapperTest extends OID4VCIssuerTestBase {
    private static final Logger LOG = Logger.getLogger(OID4VCTargetRoleMapperTest.class);

    @Test
    public void testTargetRoleMapperIncludesConfiguredClientRoles() throws Exception {
        OID4VCTestContext ctx = new OID4VCTestContext(client, jwtTypeCredentialScope);
        ClientScopeResource clientScopeResource = testRealm.admin().clientScopes().get(jwtTypeCredentialScope.getId());
        String clientAlias = "newClient-" + UUID.randomUUID();
        String roleName = "newRole";
        String username = "john-rolemapper-" + UUID.randomUUID();

        String createdClientId = createClient(clientAlias);
        createClientRole(createdClientId, roleName);
        String createdUserId = createUserWithAttributes(username);
        assignClientRoleToUser(createdUserId, createdClientId, roleName);

        ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
        mapper.setName("target-role-mapper-" + UUID.randomUUID());
        mapper.setProtocol("oid4vc");
        mapper.setProtocolMapper("oid4vc-target-role-mapper");
        mapper.setConfig(Map.of(
                "claim.name", "roles",
                "clientId", clientAlias
        ));

        String createdMapperId = null;
        try (Response response = clientScopeResource.getProtocolMappers().createMapper(mapper)) {
            createdMapperId = ApiUtil.getCreatedId(response);
        }
        try {
            CredentialIssuer issuer = wallet.getIssuerMetadata(ctx);
            OID4VCAuthorizationDetail authDetail = new OID4VCAuthorizationDetail();
            authDetail.setType(OPENID_CREDENTIAL);
            authDetail.setCredentialConfigurationId(ctx.getCredentialConfigurationId());
            authDetail.setLocations(List.of(issuer.getCredentialIssuer()));

            AuthorizationEndpointResponse authResponse = wallet.authorizationRequest()
                    .scope(ctx.getScope())
                    .authorizationDetails(authDetail)
                    .send(username, TEST_PASSWORD);

            String code = authResponse.getCode();
            assertNotNull(code, "Authorization code should not be null");

            AccessTokenResponse tokenResponse = oauth.accessTokenRequest(code)
                    .authorizationDetails(List.of(authDetail))
                    .send();
            assertEquals(200, tokenResponse.getStatusCode(), "Token response should succeed");

            String credentialIdentifier = tokenResponse.getOID4VCAuthorizationDetails().get(0)
                    .getCredentialIdentifiers().get(0);
            CredentialResponse credentialResponse = oauth.oid4vc().credentialRequest()
                    .credentialIdentifier(credentialIdentifier)
                    .proofs(wallet.generateJwtProof(ctx, ctx.getHolder()))
                    .bearerToken(tokenResponse.getAccessToken())
                    .send()
                    .getCredentialResponse();

            JsonWebToken jwt = TokenVerifier.create(
                    (String) credentialResponse.getCredentials().get(0).getCredential(),
                    JsonWebToken.class).getToken();
            VerifiableCredential vc = JsonSerialization.mapper.convertValue(jwt.getOtherClaims().get("vc"),
                    VerifiableCredential.class);

            Object rolesClaimObj = vc.getCredentialSubject().getClaims().get("roles");
            assertNotNull(rolesClaimObj, "roles claim should be present");
            assertTrue(rolesClaimObj instanceof List<?>, "roles claim should be list-like");

            List<?> rolesClaim = (List<?>) rolesClaimObj;
            assertFalse(rolesClaim.isEmpty(), "roles claim should not be empty");

            boolean targetClientRoleFound = rolesClaim.stream()
                    .filter(Map.class::isInstance)
                    .map(Map.class::cast)
                    .anyMatch(roleEntry -> clientAlias.equals(roleEntry.get("target"))
                            && List.class.isInstance(roleEntry.get("names"))
                            && ((List<?>) roleEntry.get("names")).contains(roleName));
            assertTrue(targetClientRoleFound,
                    "roles claim should contain expected role for the target client only");
        } finally {
            cleanup("logout temporary users", wallet::logout);
            String finalCreatedMapperId = createdMapperId;
            cleanup("delete temporary mapper", () -> {
                if (finalCreatedMapperId != null) {
                    clientScopeResource.getProtocolMappers().delete(finalCreatedMapperId);
                }
            });
            cleanup("delete temporary user", () -> testRealm.admin().users().delete(createdUserId));
            cleanup("delete temporary client", () -> testRealm.admin().clients().get(createdClientId).remove());
        }
    }

    private String createClient(String clientId) {
        ClientRepresentation clientRepresentation = new ClientRepresentation();
        clientRepresentation.setClientId(clientId);
        clientRepresentation.setEnabled(true);
        try (Response response = testRealm.admin().clients().create(clientRepresentation)) {
            return ApiUtil.getCreatedId(response);
        }
    }

    private void createClientRole(String clientId, String roleName) {
        ClientResource clientResource = testRealm.admin().clients().get(clientId);
        RoleRepresentation roleRepresentation = new RoleRepresentation();
        roleRepresentation.setName(roleName);
        clientResource.roles().create(roleRepresentation);
    }

    private String createUserWithAttributes(String username) {
        UserRepresentation userRepresentation = new UserRepresentation();
        userRepresentation.setUsername(username);
        userRepresentation.setEnabled(true);
        userRepresentation.setEmail(username + "@email.cz");
        userRepresentation.setEmailVerified(true);
        userRepresentation.setFirstName("John");
        userRepresentation.setLastName("Doe");
        userRepresentation.setAttributes(Map.of(
                "did", List.of("did:key:1234"),
                "address_street_address", List.of("221B Baker Street"),
                "address_locality", List.of("London")
        ));
        CredentialRepresentation password = new CredentialRepresentation();
        password.setType(CredentialRepresentation.PASSWORD);
        password.setValue(TEST_PASSWORD);
        password.setTemporary(false);
        userRepresentation.setCredentials(List.of(password));

        try (Response response = testRealm.admin().users().create(userRepresentation)) {
            return ApiUtil.getCreatedId(response);
        }
    }

    private void assignClientRoleToUser(String userId, String clientId, String roleName) {
        UserResource userResource = testRealm.admin().users().get(userId);
        RoleRepresentation roleRepresentation = testRealm.admin().clients().get(clientId).roles().get(roleName).toRepresentation();
        userResource.roles().clientLevel(clientId).add(List.of(roleRepresentation));
    }

    private void cleanup(String action, Runnable task) {
        try {
            task.run();
        } catch (Exception e) {
            LOG.warnf(e, "Failed to %s during cleanup", action);
        }
    }
}
