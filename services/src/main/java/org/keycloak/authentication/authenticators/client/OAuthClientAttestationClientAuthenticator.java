package org.keycloak.authentication.authenticators.client;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import org.keycloak.Config;
import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.common.Profile;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.AsymmetricSignatureVerifierContext;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.protocol.oauth2.attestation.AttestationChallenge;
import org.keycloak.protocol.oauth2.attestation.AttestationValidationUtil;
import org.keycloak.protocol.oauth2.attestation.AttesterJwksLoader;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.ServicesLogger;
import org.keycloak.util.JWKSUtils;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class OAuthClientAttestationClientAuthenticator extends AbstractClientAuthenticator implements EnvironmentDependentProviderFactory {

    public static final String OAUTH_CLIENT_ATTESTATION_HEADER = "OAuth-Client-Attestation";
    public static final String OAUTH_CLIENT_ATTESTATION_POP_HEADER = "OAuth-Client-Attestation-PoP";

    public static final String PROVIDER_ID = "client-attestation";
    public static final String ATTR_PREFIX = "jwt.credential";
    public static final String CERTIFICATE_ATTR = "jwt.credential.certificate";

    public static final String ALLOWED_ISSUER_ATTR = "clientattest.issuer";

    public static final String CLIENT_ATTESTATION_JWKS = "clientattest.jwks";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "OAuth 2.0 Client Attestation";
    }

    @Override
    public String getHelpText() {
        return "OAuth 2.0 Attestation based Client Authentication validates client based on signed client attestation JWT issued by a Client Attester and signed with the Client private key. See https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07";
    }

    @Override
    public void authenticateClient(ClientAuthenticationFlowContext context) {
        var httpHeaders = context.getHttpRequest().getHttpHeaders();
        RealmModel realm = context.getRealm();

        // Extract attestation headers
        String clientAttestationHeader = httpHeaders.getHeaderString(OAUTH_CLIENT_ATTESTATION_HEADER);
        if (clientAttestationHeader == null || clientAttestationHeader.isEmpty()) {
            failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION, 
                    "Missing OAuth-Client-Attestation header", null);
            return;
        }

        String clientAttestationPopHeader = httpHeaders.getHeaderString(OAUTH_CLIENT_ATTESTATION_POP_HEADER);

        String oauthClientAttestation = clientAttestationHeader;
        String oauthClientAttestationPoP = clientAttestationPopHeader;
        
        // Handle Concatenated Serialization for Client Attestations
        // see: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07#section-7
        if (clientAttestationHeader.contains("~")) {
            String[] attestationAndPop = clientAttestationHeader.split("~", 2);
            if (attestationAndPop.length != 2) {
                failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                        "Invalid concatenated serialization format", null);
                return;
            }
            oauthClientAttestation = attestationAndPop[0];
            oauthClientAttestationPoP = attestationAndPop[1];
        }

        if (oauthClientAttestationPoP == null || oauthClientAttestationPoP.isEmpty()) {
            failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                    "Missing OAuth-Client-Attestation-PoP header", null);
            return;
        }

        // Parse and validate Client Attestation JWT
        JWSInput clientAttestationJws;
        JWSHeader clientAttestationHeaderObj;
        JsonWebToken clientAttestation;
        String clientAttestationAlg;
        try {
            clientAttestationJws = new JWSInput(oauthClientAttestation);
            clientAttestationHeaderObj = clientAttestationJws.getHeader();
            clientAttestation = clientAttestationJws.readJsonContent(JsonWebToken.class);
            clientAttestationAlg = clientAttestationHeaderObj.getRawAlgorithm();
        } catch (JWSInputException e) {
            ServicesLogger.LOGGER.errorValidatingAssertion(e);
            failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                    "Failed to parse Client Attestation JWT: " + e.getMessage(), null);
            return;
        }

        // Validate typ header for Attestation JWT
        try {
            AttestationValidationUtil.validateTypHeader(clientAttestationHeaderObj, "client-attestation+jwt");
        } catch (VerificationException e) {
            failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                    e.getMessage(), null);
            return;
        }

        // Validate algorithm for Attestation JWT
        try {
            AttestationValidationUtil.validateAlgorithm(clientAttestationAlg);
        } catch (VerificationException e) {
            failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                    "Invalid algorithm: " + e.getMessage(), null);
            return;
        }

        // Extract and validate client ID from subject
        String clientId = clientAttestation.getSubject();
        if (clientId == null || clientId.isEmpty()) {
            failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                    "Missing sub claim in Client Attestation", null);
            return;
        }

        context.getEvent().client(clientId);

        // Get client
        ClientModel client = context.getSession().clients().getClientByClientId(realm, clientId);
        if (client == null) {
            context.failure(AuthenticationFlowError.CLIENT_NOT_FOUND, null);
            return;
        }

        context.setClient(client);

        if (!client.isEnabled()) {
            context.failure(AuthenticationFlowError.CLIENT_DISABLED, null);
            return;
        }

        // Validate issuer
        String issuer = clientAttestation.getIssuer();
        if (issuer == null || issuer.isEmpty()) {
            failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                    "Missing iss claim in Client Attestation", null);
            return;
        }

        String allowedIssuer = client.getAttribute(ALLOWED_ISSUER_ATTR);
        if (allowedIssuer == null || allowedIssuer.isEmpty()) {
            failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                    "Client attestation issuer not configured", null);
            return;
        }

        // Validate issuer matches (exact match, not endsWith)
        if (!issuer.equals(allowedIssuer)) {
            context.getEvent().detail("client_attestation_issuer", issuer);
            context.getEvent().detail("allowed_issuer", allowedIssuer);
            failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                    "Issuer mismatch", null);
            return;
        }

        // Load attester public keys and verify Client Attestation signature
        String kid = clientAttestationHeaderObj.getKeyId();
        KeyWrapper attesterKeyWrapper = AttesterJwksLoader.getAttesterPublicKeyWrapper(
                context.getSession(), client, realm, issuer, kid, clientAttestationAlg);
        
        if (attesterKeyWrapper == null) {
            failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                    "Unable to load attester public key", null);
            return;
        }

        // Verify Client Attestation signature
        try {
            AsymmetricSignatureVerifierContext attesterVerifierContext = 
                    AttestationValidationUtil.createVerifierContext(attesterKeyWrapper, clientAttestationAlg);
            
            // Validate claims (iss, sub, aud, nbf, exp, etc.)
            // Note: aud claim validation may need to be adjusted based on spec requirements
            AttestationValidationUtil.validateJwtClaims(oauthClientAttestation, issuer, clientId, 
                    null, attesterVerifierContext);
        } catch (VerificationException e) {
            context.getEvent().error("invalid_client_attestation_signature");
            failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                    "Client Attestation signature validation failed: " + e.getMessage(), null);
            return;
        }

        // Extract cnf claim
        @SuppressWarnings("unchecked")
        var cnf = (Map<String, Object>) clientAttestation.getOtherClaims().get("cnf");
        if (cnf == null) {
            failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                    "Missing cnf claim in Client Attestation", null);
            return;
        }

        // Extract jwk from cnf
        @SuppressWarnings("unchecked")
        var jwkMap = (Map<String, Object>) cnf.get("jwk");
        if (jwkMap == null) {
            failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                    "Missing jwk in cnf claim", null);
            return;
        }

        // Validate that jwk contains only public key (no private key components)
        try {
            AttestationValidationUtil.validateJwkIsPublicKeyOnly(jwkMap);
        } catch (VerificationException e) {
            failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                    "JWK in cnf contains private key material: " + e.getMessage(), null);
            return;
        }

        // Create KeyWrapper from jwk
        KeyWrapper keyWrapper;
        try {
            String jwkString = JsonSerialization.writeValueAsString(jwkMap);
            JWKParser parser = JWKParser.create().parse(jwkString);
            JWK jwk = parser.getJwk();
            keyWrapper = JWKSUtils.getKeyWrapper(jwk);
            if (keyWrapper == null) {
                failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                        "Failed to create key wrapper from JWK", null);
                return;
            }
        } catch (IOException | RuntimeException e) {
            context.getEvent().error("invalid_client_attestation_invalid_jwk");
            failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                    "Invalid JWK in cnf: " + e.getMessage(), null);
            return;
        }

        // Parse and validate PoP JWT
        JWSInput popJws;
        JWSHeader popHeader;
        JsonWebToken clientAttestationPop;
        String popAlg;
        try {
            popJws = new JWSInput(oauthClientAttestationPoP);
            popHeader = popJws.getHeader();
            clientAttestationPop = popJws.readJsonContent(JsonWebToken.class);
            popAlg = popHeader.getRawAlgorithm();
        } catch (JWSInputException e) {
            context.getEvent().error("invalid_client_attestation_pop_parse");
            failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                    "Failed to parse PoP JWT: " + e.getMessage(), null);
            return;
        }

        // Validate typ header for PoP JWT
        try {
            AttestationValidationUtil.validateTypHeader(popHeader, "pop+jwt");
        } catch (VerificationException e) {
            failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                    "Invalid PoP typ header: " + e.getMessage(), null);
            return;
        }

        // Validate algorithm for PoP JWT
        try {
            AttestationValidationUtil.validateAlgorithm(popAlg);
        } catch (VerificationException e) {
            failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                    "Invalid PoP algorithm: " + e.getMessage(), null);
            return;
        }

        // Verify PoP signature using key from cnf
        try {
            AsymmetricSignatureVerifierContext popVerifierContext = 
                    AttestationValidationUtil.createVerifierContext(keyWrapper, popAlg);
            
            // Validate PoP claims (iss, sub, aud, nbf, exp, etc.)
            // Note: aud claim validation may need to be adjusted based on spec requirements
            AttestationValidationUtil.validateJwtClaims(oauthClientAttestationPoP, clientId, clientId,
                    null, popVerifierContext);
        } catch (VerificationException e) {
            context.getEvent().error("invalid_client_attestation_pop_signature");
            failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                    "PoP signature validation failed: " + e.getMessage(), null);
            return;
        }

        // Validate client_id matches Attestation sub and PoP iss
        try {
            AttestationValidationUtil.validateClientIdMatches(clientId, 
                    clientAttestation.getSubject(), clientAttestationPop.getIssuer());
        } catch (VerificationException e) {
            failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                    e.getMessage(), null);
            return;
        }

        // Verify challenge (replaced nonce with challenge)
        String challenge = (String) clientAttestationPop.getOtherClaims().get("challenge");
        if (challenge == null || challenge.isEmpty()) {
            failWithAttestationError(context, OAuthErrorException.INVALID_CLIENT_ATTESTATION,
                    "Missing challenge claim in PoP JWT", null);
            return;
        }

        SingleUseObjectProvider singleUse = context.getSession().getProvider(SingleUseObjectProvider.class);
        Map<String, String> challengeNotes = singleUse.get(AttestationChallenge.generateChallengeKey(realm, challenge));
        if (challengeNotes == null) {
            context.getEvent().error("invalid_client_attestation_challenge");
            failWithAttestationError(context, OAuthErrorException.USE_FRESH_ATTESTATION,
                    "Challenge not found or already used", null);
            return;
        }

        // Mark challenge as used (optional, depending on spec requirements)
        // singleUse.remove(AttestationChallenge.generateChallengeKey(realm, challenge));

        context.success();
    }

    /**
     * Helper method to fail with proper attestation error response format.
     */
    @SuppressWarnings("unused")
    private void failWithAttestationError(ClientAuthenticationFlowContext context, String error, 
                                         String errorDescription, String challengeHeader) {
        Response.ResponseBuilder responseBuilder = Response.status(Response.Status.UNAUTHORIZED)
                .type(jakarta.ws.rs.core.MediaType.APPLICATION_JSON_TYPE);
        
        if (challengeHeader != null) {
            responseBuilder.header(HttpHeaders.WWW_AUTHENTICATE, challengeHeader);
        }
        
        org.keycloak.representations.idm.OAuth2ErrorRepresentation errorRep = 
                new org.keycloak.representations.idm.OAuth2ErrorRepresentation(error, errorDescription);
        Response challengeResponse = responseBuilder.entity(errorRep).build();
        
        context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS, challengeResponse);
    }


    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public List<ProviderConfigProperty> getConfigPropertiesPerClient() {
        var list = ProviderConfigurationBuilder.create() //
                .property().name(ALLOWED_ISSUER_ATTR) //
                .type(ProviderConfigProperty.STRING_TYPE) //
                .label("Allowed Issuer") //
                .defaultValue(null) //
                .helpText("Allowed issuer of the client attestation.") //
                .add() //

                .property().name(CLIENT_ATTESTATION_JWKS) //
                .type(ProviderConfigProperty.TEXT_TYPE) //
                .label("Client Attestation JWKS") //
                .defaultValue(null) //
                .helpText("JWKS for the Client Attestation") //
                .add() //

                .build();

        return list;
    }

    @Override
    public Map<String, Object> getAdapterConfiguration(ClientModel client) {
        return Collections.emptyMap();
    }

    @Override
    public Set<String> getProtocolAuthenticatorMethods(String loginProtocol) {
        if (loginProtocol.equals(OIDCLoginProtocol.LOGIN_PROTOCOL)) {
            Set<String> results = new HashSet<>();
            results.add(OIDCLoginProtocol.OAUTH2_CLIENT_ATTESTATION);
            return results;
        } else {
            return Collections.emptySet();
        }
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.OAUTH_ABCA);
    }
}
