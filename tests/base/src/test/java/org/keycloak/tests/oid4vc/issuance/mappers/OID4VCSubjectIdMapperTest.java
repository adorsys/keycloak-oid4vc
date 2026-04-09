package org.keycloak.tests.oid4vc.issuance.mappers;

import java.util.List;

import org.keycloak.TokenVerifier;
import org.keycloak.admin.client.resource.ClientScopeResource;
import org.keycloak.protocol.oid4vc.model.CredentialIssuer;
import org.keycloak.protocol.oid4vc.model.CredentialResponse;
import org.keycloak.protocol.oid4vc.model.OID4VCAuthorizationDetail;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.tests.oid4vc.OID4VCIssuerTestBase;
import org.keycloak.tests.oid4vc.OID4VCTestContext;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.testsuite.util.oauth.AuthorizationEndpointResponse;
import org.keycloak.util.JsonSerialization;

import org.junit.jupiter.api.Test;

import static org.keycloak.OID4VCConstants.OPENID_CREDENTIAL;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@KeycloakIntegrationTest(config = OID4VCIssuerTestBase.VCTestServerConfig.class)
public class OID4VCSubjectIdMapperTest extends OID4VCIssuerTestBase {

    @Test
    public void testSubjectIdMapperReadsUserModelId() throws Exception {
        OID4VCTestContext ctx = new OID4VCTestContext(client, jwtTypeCredentialScope);
        UserRepresentation user = getExistingUser(TEST_USER);

        ClientScopeResource clientScopeResource = testRealm.admin().clientScopes().get(jwtTypeCredentialScope.getId());
        ProtocolMapperRepresentation subjectIdMapper = clientScopeResource.getProtocolMappers().getMappers().stream()
                .filter(pm -> "oid4vc-subject-id-mapper".equals(pm.getProtocolMapper()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No oid4vc-subject-id-mapper configured"));

        String originalUserAttribute = subjectIdMapper.getConfig().get("userAttribute");
        String originalClaimName = subjectIdMapper.getConfig().get("claim.name");

        try {
            subjectIdMapper.getConfig().put("userAttribute", "id");
            subjectIdMapper.getConfig().put("claim.name", "id");
            clientScopeResource.getProtocolMappers().update(subjectIdMapper.getId(), subjectIdMapper);

            CredentialIssuer issuer = wallet.getIssuerMetadata(ctx);
            OID4VCAuthorizationDetail authDetail = new OID4VCAuthorizationDetail();
            authDetail.setType(OPENID_CREDENTIAL);
            authDetail.setCredentialConfigurationId(ctx.getCredentialConfigurationId());
            authDetail.setLocations(List.of(issuer.getCredentialIssuer()));

            AuthorizationEndpointResponse authResponse = wallet.authorizationRequest()
                    .scope(ctx.getScope())
                    .authorizationDetails(authDetail)
                    .send(TEST_USER, TEST_PASSWORD);

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

            CredentialResponse.Credential credentialWrapper = credentialResponse.getCredentials().get(0);
            JsonWebToken jwt = TokenVerifier.create((String) credentialWrapper.getCredential(), JsonWebToken.class)
                    .getToken();

            Object vc = jwt.getOtherClaims().get("vc");
            VerifiableCredential verifiableCredential = JsonSerialization.mapper.convertValue(vc, VerifiableCredential.class);

            Object idClaim = verifiableCredential.getCredentialSubject().getClaims().get("id");
            assertEquals(user.getId(), idClaim, "Subject id claim should be mapped from UserModel.getId()");
        } finally {
            if (originalUserAttribute != null) {
                subjectIdMapper.getConfig().put("userAttribute", originalUserAttribute);
            } else {
                subjectIdMapper.getConfig().remove("userAttribute");
            }

            if (originalClaimName != null) {
                subjectIdMapper.getConfig().put("claim.name", originalClaimName);
            } else {
                subjectIdMapper.getConfig().remove("claim.name");
            }
            clientScopeResource.getProtocolMappers().update(subjectIdMapper.getId(), subjectIdMapper);
        }
    }
}
