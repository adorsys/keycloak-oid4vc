package org.keycloak.testsuite.oid4vc.issuance.credentialoffer.preauth;

import java.util.List;

import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.ECDSASignatureSignerContext;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProvider;
import org.keycloak.protocol.oid4vc.issuance.credentialoffer.preauth.JwtPreAuthCodeHandler;
import org.keycloak.protocol.oid4vc.model.CredentialsOffer;
import org.keycloak.protocol.oid4vc.model.JwtPreAuthCode;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.testsuite.oid4vc.issuance.signing.OID4VCIssuerEndpointTest;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.util.JsonSerialization;

import org.apache.http.HttpStatus;
import org.junit.Test;

import static org.keycloak.protocol.oid4vc.issuance.credentialoffer.CredentialOfferStorage.CredentialOfferState;
import static org.keycloak.protocol.oid4vc.issuance.credentialoffer.preauth.JwtPreAuthCodeHandler.PRE_AUTH_CODE_TYP;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class JwtPreAuthCodeHandlerTest extends OID4VCIssuerEndpointTest {

    @Test
    public void shouldGenerateValidPreAuthCode() {
        // Initiate the flow by creating a credential offer state
        String offerStateJson = createPreAuthOffer();

        // Create a pre-auth code for the offer state
        String preAuthorizedCode = testingClient.server(TEST_REALM_NAME).fetch((session) -> {
            JwtPreAuthCodeHandler handler = new JwtPreAuthCodeHandler(session);
            CredentialOfferState offerState = JsonSerialization.valueFromString(
                    offerStateJson, CredentialOfferState.class);

            // Create pre-auth code and quickly check that it is a well-structured JWT
            String preAuthCode = handler.createPreAuthCode(offerState);
            assertValidPreAuthCodeJwt(preAuthCode);

            // Verify pre-auth code and recover offer state
            try {
                CredentialOfferState recoveredOfferState = handler.verifyPreAuthCode(preAuthCode);
                assertEquals("Recovered offer state must match original", offerState, recoveredOfferState);
                return preAuthCode;
            } catch (VerificationException e) {
                throw new RuntimeException(e);
            }
        }, String.class);

        // Ensure that the pre-auth code can be exchanged for an access token
        AccessTokenResponse accessTokenResponse = exchangePreAuthCodeForAccessToken(preAuthorizedCode);
        assertEquals(HttpStatus.SC_OK, accessTokenResponse.getStatusCode());
        assertNotNull("Access token must not be null", accessTokenResponse.getAccessToken());
    }

    @Test
    public void mustRejectNonPreAuthCodeJwts() {
        // Get a valid but not pre-auth code JWT
        String imposterPreAuthCode = testingClient.server(TEST_REALM_NAME).fetch((session) -> {
            // Build a random JWT
            JsonWebToken jwt = new JsonWebToken()
                    .issuer("issuer")
                    .addAudience("audience")
                    .issuedNow()
                    .exp((long) (Time.currentTime() + 60));

            // Sign to yield a valid JWT
            RealmModel realm = session.getContext().getRealm();
            KeyWrapper keyWrapper = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.ES256);
            ECDSASignatureSignerContext signer = new ECDSASignatureSignerContext(keyWrapper);
            return new JWSBuilder().jsonContent(jwt).sign(signer);
        }, String.class);

        // Ensure that it fails handler verification
        testingClient.server(TEST_REALM_NAME).run((session) -> {
            JwtPreAuthCodeHandler handler = new JwtPreAuthCodeHandler(session);

            VerificationException exception = assertThrows(VerificationException.class,
                    () -> handler.verifyPreAuthCode(imposterPreAuthCode));

            assertEquals("Invalid or missing JWT typ header for pre-auth code: " +
                    "expected 'oid4vci-pre-auth-code+jwt' got 'null'", exception.getMessage());
        });

        // Ensure that it cannot be exchanged for an access token
        AccessTokenResponse accessTokenResponse = exchangePreAuthCodeForAccessToken(imposterPreAuthCode);
        assertEquals(HttpStatus.SC_BAD_REQUEST, accessTokenResponse.getStatusCode());
        assertEquals("Pre-authorized code failed handler verification",
                accessTokenResponse.getErrorDescription());
    }

    @Test
    public void mustRejectExpiredPreAuthCodeJwts() {
        // Initiate the flow by creating a credential offer state
        String offerStateJson = createPreAuthOffer();

        // Assert that an expired pre-auth code fails verification
        testingClient.server(TEST_REALM_NAME).run((session) -> {
            JwtPreAuthCodeHandler handler = new JwtPreAuthCodeHandler(session);
            CredentialOfferState offerState = JsonSerialization.valueFromString(
                    offerStateJson, CredentialOfferState.class);
            String preAuthCode = handler.createPreAuthCode(offerState);

            Time.setOffset(120); // Move time forward to ensure code is expired
            VerificationException exception = assertThrows(VerificationException.class,
                    () -> handler.verifyPreAuthCode(preAuthCode));

            assertTrue(exception.getMessage().startsWith("Jwt pre-auth code not valid:"));
        });
    }

    @Test
    public void mustRejectReplayedPreAuthCodeJwts() {
        // Initiate the flow by creating a credential offer state
        String offerStateJson = createPreAuthOffer();

        // Create a pre-auth code for the offer state
        String preAuthorizedCode = testingClient.server(TEST_REALM_NAME).fetch((session) -> {
            JwtPreAuthCodeHandler handler = new JwtPreAuthCodeHandler(session);
            CredentialOfferState offerState = JsonSerialization.valueFromString(
                    offerStateJson, CredentialOfferState.class);

            // Create pre-auth code and quickly check that it is a well-structured JWT
            String preAuthCode = handler.createPreAuthCode(offerState);
            assertValidPreAuthCodeJwt(preAuthCode);
            return preAuthCode;
        }, String.class);

        // First use: the pre-auth code can be exchanged for an access token
        AccessTokenResponse accessTokenResponse = exchangePreAuthCodeForAccessToken(preAuthorizedCode);
        assertEquals(HttpStatus.SC_OK, accessTokenResponse.getStatusCode());

        // Second use: the same pre-auth code must be rejected as replayed
        AccessTokenResponse replayResponse = exchangePreAuthCodeForAccessToken(preAuthorizedCode);
        assertEquals(HttpStatus.SC_BAD_REQUEST, replayResponse.getStatusCode());
        assertEquals("Pre-authorized code has already been used",
                replayResponse.getErrorDescription());
    }

    private String createPreAuthOffer() {
        return testingClient.server(TEST_REALM_NAME).fetchString((session) -> {
            CredentialsOffer credOffer = new CredentialsOffer()
                    .setCredentialIssuer(OID4VCIssuerWellKnownProvider.getIssuer(session.getContext()))
                    .setCredentialConfigurationIds(List.of(sdJwtTypeCredentialConfigurationIdName));

            RealmModel realm = session.getContext().getRealm();
            UserModel user = session.users().getUserByUsername(realm, "john");

            return new CredentialOfferState(
                    credOffer, "test-app", user.getId(), Time.currentTime() + 60);
        });
    }

    private AccessTokenResponse exchangePreAuthCodeForAccessToken(String preAuthCode) {
        final String endpoint = getRealmPath(TEST_REALM_NAME);
        OIDCConfigurationRepresentation oidcConfig = getAuthorizationMetadata(endpoint);

        return oauth.oid4vc()
                .preAuthorizedCodeGrantRequest(preAuthCode)
                .endpoint(oidcConfig.getTokenEndpoint())
                .send();
    }

    private static void assertValidPreAuthCodeJwt(String jwt) {
        JWSInput jws;
        JwtPreAuthCode payload;

        try {
            jws = new JWSInput(jwt);
            payload = jws.readJsonContent(JwtPreAuthCode.class);
        } catch (JWSInputException e) {
            throw new RuntimeException(e);
        }

        assertEquals("Must be of type PreAuthCode", PRE_AUTH_CODE_TYP, jws.getHeader().getType());
        assertNotNull("Must embed a credential offer state", payload.getCredentialOfferState());
        assertNotNull("Must be salted", payload.getSalt());
    }
}
