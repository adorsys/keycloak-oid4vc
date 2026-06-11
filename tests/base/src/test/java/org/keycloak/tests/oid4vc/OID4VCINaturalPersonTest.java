package org.keycloak.tests.oid4vc;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.keycloak.TokenVerifier;
import org.keycloak.broker.trust.DefaultTrustIdentityProviderConfig;
import org.keycloak.broker.trust.DefaultTrustIdentityProviderFactory;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.model.CredentialDefinition;
import org.keycloak.protocol.oid4vc.model.CredentialResponse;
import org.keycloak.protocol.oid4vc.model.CredentialScopeRepresentation;
import org.keycloak.protocol.oid4vc.model.Proofs;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.annotations.TestSetup;
import org.keycloak.tests.oid4vc.abca.OIDCMockClientAttester;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.testsuite.util.oauth.AuthorizationEndpointResponse;
import org.keycloak.testsuite.util.oauth.PkceGenerator;
import org.keycloak.util.JsonSerialization;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.shaded.org.checkerframework.checker.units.qual.K;

import static org.keycloak.OID4VCConstants.CLAIM_NAME_VCT;
import static org.keycloak.VCFormat.JWT_VC;
import static org.keycloak.VCFormat.SD_JWT_VC;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import static org.keycloak.tests.oid4vc.OID4VCProofTestUtils.createEcKeyPair;

@KeycloakIntegrationTest(config = OID4VCIssuerTestBase.VCTestServerConfig.class)
public class OID4VCINaturalPersonTest extends OID4VCIssuerTestBase {

    private static KeyWrapper attestationKey;
    private static String attesterJwks;

    @TestSetup
    public void configure() throws Exception {
        attestationKey = createEcKeyPair("oid4vci-trusted-attester-jwk");
        JWK jwk = JWKBuilder.create()
                .kid(attestationKey.getKid())
                .ec(attestationKey.getPublicKey());;
        JSONWebKeySet jwks = new JSONWebKeySet();
        jwks.setKeys(new JWK[] { jwk });
        attesterJwks = JsonSerialization.writeValueAsString(jwks);
    }

    @BeforeEach
    void beforeEach() {
        oauth.client(pubClient.getClientId());
        String jwks = attesterJwks;
        runOnServer.run(session -> {
            RealmModel realm = session.getContext().getRealm();
            configureTrustIdentityProvider(realm, OID4VCI_ATTESTER_DEFAULT_TRUST_IDP_ALIAS,
                    DefaultTrustIdentityProviderFactory.PROVIDER_ID,
                    Map.of(DefaultTrustIdentityProviderConfig.TRUSTED_JWKS, jwks));
        });
    }

    @Test
    public void testNaturalPersonJwt_AttestationProof() throws Exception {

        var ctx = new OID4VCTestContext(client, jwtNaturalPersonCredentialScope);

        Proofs proofs = wallet.generateAttestationProof(ctx, attestationKey);

        String accessToken = getAccessToken(ctx);
        CredentialResponse credResponse = getCredentialResponse(ctx, accessToken, proofs);
        verifyCredentialResponse(ctx, ctx.getHolder(), credResponse);
    }

    @Test
    public void testNaturalPersonJwt_JwtProof() throws Exception {

        var ctx = new OID4VCTestContext(client, jwtNaturalPersonCredentialScope);

        String accessToken = getAccessToken(ctx);
        Proofs proofs = wallet.generateJwtProof(ctx);
        CredentialResponse credResponse = getCredentialResponse(ctx, accessToken, proofs);
        verifyCredentialResponse(ctx, ctx.getHolder(), credResponse);
    }

    @Test
    public void testNaturalPersonSdJwt_AttestationProof() throws Exception {

        var ctx = new OID4VCTestContext(client, sdJwtNaturalPersonCredentialScope);

        Proofs proofs = wallet.generateAttestationProof(ctx, attestationKey);

        String accessToken = getAccessToken(ctx);
        CredentialResponse credResponse = getCredentialResponse(ctx, accessToken, proofs);
        verifyCredentialResponse(ctx, ctx.getHolder(), credResponse);
    }


    @Test
    public void testNaturalPersonSdJwt_JwtProof() throws Exception {

        var ctx = new OID4VCTestContext(client, sdJwtNaturalPersonCredentialScope);

        String accessToken = getAccessToken(ctx);
        Proofs proofs = wallet.generateJwtProof(ctx);
        CredentialResponse credResponse = getCredentialResponse(ctx, accessToken, proofs);
        verifyCredentialResponse(ctx, ctx.getHolder(), credResponse);
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private String getAccessToken(OID4VCTestContext ctx) {

        PkceGenerator pkce = PkceGenerator.s256();
        AuthorizationEndpointResponse authResponse = wallet
                .authorizationRequest()
                .scope(ctx.getScope())
                .codeChallenge(pkce)
                .send(ctx.getHolder(), TEST_PASSWORD);
        String authCode = authResponse.getCode();
        assertNotNull(authCode, "No authCode");

        AccessTokenResponse tokenResponse = wallet.accessTokenRequest(ctx, authCode)
                .codeVerifier(pkce)
                .send();
        String accessToken = wallet.validateHolderAccessToken(ctx, tokenResponse);
        assertNotNull(accessToken, "No accessToken");
        return accessToken;
    }

    private CredentialResponse getCredentialResponse(OID4VCTestContext ctx, String accessToken, Proofs proofs) {

        String authorizedIdentifier = ctx.getAuthorizedCredentialIdentifier();
        assertNotNull(authorizedIdentifier, "No authorized credential identifier");

        CredentialResponse credResponse = wallet.credentialRequest(ctx, accessToken)
                .credentialIdentifier(authorizedIdentifier)
                .proofs(proofs)
                .send().getCredentialResponse();
        return credResponse;
    }

    private void verifyCredentialResponse(OID4VCTestContext ctx, String expUser, CredentialResponse credResponse) throws Exception {

        CredentialScopeRepresentation credScope = ctx.getCredentialScope();
        String issuer = wallet.getIssuerMetadata(ctx).getCredentialIssuer();
        CredentialResponse.Credential credentialObj = credResponse.getCredentials().get(0);
        assertNotNull(credentialObj, "The first credential in the array should not be null");

        switch (credScope.getFormat()) {
            case JWT_VC -> {
                JsonWebToken vcJwt = TokenVerifier.create((String) credentialObj.getCredential(), JsonWebToken.class).getToken();
                assertEquals(issuer, vcJwt.getIssuer());
                Object vc = vcJwt.getOtherClaims().get("vc");
                VerifiableCredential credential = JsonSerialization.mapper.convertValue(vc, VerifiableCredential.class);
                List<String> expectedCredentialTypes = new ArrayList<>();
                expectedCredentialTypes.add(CredentialDefinition.VERIFIABLE_CREDENTIAL_TYPE);
                expectedCredentialTypes.addAll(credScope.getSupportedCredentialTypes());
                assertEquals(expectedCredentialTypes, credential.getType());
                assertEquals(URI.create(issuer), credential.getIssuer());
                assertEquals(expUser + "@email.cz", credential.getCredentialSubject().getClaims().get("email"));
            }
            case SD_JWT_VC -> {
                SdJwtVP sdJwtVP = SdJwtVP.of(credentialObj.getCredential().toString());
                IssuerSignedJWT issuerSignedJWT = sdJwtVP.getIssuerSignedJWT();
                JsonWebToken vcSdJwt = TokenVerifier.create(issuerSignedJWT.getJws(), JsonWebToken.class).getToken();
                Map<String, Object> otherClaims = vcSdJwt.getOtherClaims();
                assertEquals(issuer, vcSdJwt.getIssuer());
                assertEquals(credScope.getVct(), otherClaims.get(CLAIM_NAME_VCT));

                Map<String, String> claims = sdJwtVP.getClaims().values().stream().collect(Collectors.toMap(
                        arrayNode -> arrayNode.get(1).asText(),
                        arrayNode -> arrayNode.get(2).asText()
                ));
                assertEquals(Map.of(
                        "firstName", "Alice",
                        "familyName", "Wonderland",
                        "email", "alice@email.cz",
                        "sub", "did:key:5678"
                ), claims);
            }
        }
    }
}
