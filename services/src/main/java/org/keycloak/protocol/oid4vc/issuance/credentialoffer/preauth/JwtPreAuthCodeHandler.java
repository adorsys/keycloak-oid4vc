package org.keycloak.protocol.oid4vc.issuance.credentialoffer.preauth;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.oid4vc.issuance.credentialoffer.CredentialOfferStorage.CredentialOfferState;
import org.keycloak.protocol.oid4vc.model.JwtPreAuthCode;
import org.keycloak.protocol.oidc.OIDCWellKnownProviderFactory;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.utils.StringUtil;
import org.keycloak.wellknown.WellKnownProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.keycloak.constants.OID4VCIConstants.OID4VC_PROTOCOL;

/**
 * Implementation of {@link PreAuthCodeHandler} for JWT pre-authorized codes.
 */
public class JwtPreAuthCodeHandler implements PreAuthCodeHandler {

    private static final Logger logger = LoggerFactory.getLogger(JwtPreAuthCodeHandler.class);

    private final KeycloakSession session;
    private final RealmModel realm;

    public JwtPreAuthCodeHandler(KeycloakSession session) {
        this.session = session;
        this.realm = session.getContext().getRealm();
    }

    @Override
    public String createPreAuthCode(CredentialOfferState offerState) {
        // Building
        String issuer = offerState.getCredentialsOffer().getCredentialIssuer();
        JwtPreAuthCode jwtBody = (JwtPreAuthCode) new JwtPreAuthCode()
                .credentialOfferState(offerState)
                .issuer(issuer)
                .addAudience(getTokenEndpoint())
                .issuedNow()
                .exp((long) offerState.getExpiration());

        // Signing
        SignatureSignerContext signer = getSignerContext(offerState);
        return new JWSBuilder().jsonContent(jwtBody).sign(signer);
    }

    @Override
    public CredentialOfferState verifyPreAuthCode(String preAuthCode) throws VerificationException {
        // Parse the JWT
        JWSInput jwsInput;
        try {
            jwsInput = new JWSInput(preAuthCode);
        } catch (JWSInputException e) {
            throw new VerificationException("Failed to parse pre-auth code: Not JWT", e);
        }

        // Verify JWT
        TokenVerifier<JwtPreAuthCode> verifier = TokenVerifier.create(preAuthCode, JwtPreAuthCode.class);
        // TODO: Add checks to match issuer, audience, and expiration
        verifier.verifierContext(getVerifierContext(jwsInput.getHeader()));
        verifier.verify();

        // Parse payload as JwtPreAuthCode and extract CredentialOfferState
        try {
            JwtPreAuthCode jwtBody = jwsInput.readJsonContent(JwtPreAuthCode.class);
            return jwtBody.getCredentialOfferState();
        } catch (JWSInputException e) {
            throw new VerificationException("Failed to recover credential offer state", e);
        }
    }

    private String getTokenEndpoint() {
        WellKnownProvider oidcProvider = session.getProvider(
                WellKnownProvider.class, OIDCWellKnownProviderFactory.PROVIDER_ID);
        OIDCConfigurationRepresentation oidcConfig = (OIDCConfigurationRepresentation) oidcProvider.getConfig();
        return oidcConfig.getTokenEndpoint();
    }

    /**
     * Retrieves the preferred signing algorithms for JWT pre-auth codes,
     * based on the configuration of credentials under consideration.
     */
    private List<String> getPreferredSigningAlgs(CredentialOfferState offerState) {
        List<String> configIds = offerState.getCredentialsOffer().getCredentialConfigurationIds();

        Stream<CredentialScopeModel> credentialScopes = session.clientScopes()
                .getClientScopesByProtocol(realm, OID4VC_PROTOCOL)
                .map(CredentialScopeModel::new)
                .filter(s -> configIds.contains(
                        s.getCredentialConfigurationId()
                ));

        return credentialScopes.map(CredentialScopeModel::getSigningAlg)
                .filter(StringUtil::isNotBlank)
                .distinct()
                .toList();
    }

    /**
     * Retrieves a SignatureSignerContext for signing JWT pre-auth codes, based on the preferred
     * signing algorithms derived from the credential offer state.
     */
    private SignatureSignerContext getSignerContext(CredentialOfferState offerState) {
        List<String> preferredAlgs = getPreferredSigningAlgs(offerState);
        logger.debug("Preferred signing algorithms for JWT pre-auth code: {}", preferredAlgs);

        // Default to Algorithm.ES256 if no preferred algorithm is found or signing key available
        List<String> algs = new ArrayList<>(preferredAlgs);
        if (!algs.contains(Algorithm.ES256)) {
            algs.add(Algorithm.ES256);
        }

        for (String alg : algs) {
            try {
                KeyWrapper signingKey = session.keys().getActiveKey(realm, KeyUse.SIG, alg);
                if (signingKey == null) {
                    logger.debug("No active signing key found for algorithm {}, skipping", alg);
                    continue;
                }

                SignatureProvider signatureProvider = session.getProvider(
                        SignatureProvider.class,
                        signingKey.getAlgorithm());

                return signatureProvider.signer(signingKey);
            } catch (RuntimeException ignored) {
                logger.debug("No active signing key/context found for algorithm {}, skipping", alg);
            }
        }

        throw new RuntimeException("No signing key/context available for JWT pre-auth code signing");
    }

    /**
     * Retrieves a SignatureVerifierContext for verifying JWT pre-auth codes,
     * based on signing metadata in the JWS header and available keys.
     */
    public SignatureVerifierContext getVerifierContext(JWSHeader jwsHeader) throws VerificationException {
        String kid = jwsHeader.getKeyId();
        String alg = jwsHeader.getAlgorithm().toString();
        KeyWrapper key = session.keys().getKey(realm, kid, KeyUse.SIG, alg);

        if (key == null) {
            throw new VerificationException(String.format(
                    "No key found for verifying JWT pre-auth code with alg '%s' and kid '%s'",
                    alg, kid));
        }

        SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, key.getAlgorithm());
        return signatureProvider.verifier(key);
    }

    @Override
    public void close() {
    }
}
