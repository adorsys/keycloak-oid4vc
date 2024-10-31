package org.keycloak.protocol.oid4vc.issuance.credentials;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.jboss.logging.Logger;
import org.keycloak.protocol.oid4vc.issuance.VCIssuanceContext;
import org.keycloak.protocol.oid4vc.issuance.signing.SdJwtSigningService;
import org.keycloak.protocol.oid4vc.model.CredentialConfigId;
import org.keycloak.protocol.oid4vc.model.CredentialSubject;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.protocol.oid4vc.model.VerifiableCredentialType;
import org.keycloak.sdjwt.DisclosureSpec;
import org.keycloak.sdjwt.SdJwt;
import org.keycloak.sdjwt.SdJwtUtils;

import java.util.List;
import java.util.stream.IntStream;

public class SdJwtCredentialBuilder implements CredentialBuilder {
    private static final Logger LOGGER = Logger.getLogger(SdJwtSigningService.class);

    private static final String ISSUER_CLAIM = "iss";
    private static final String VERIFIABLE_CREDENTIAL_TYPE_CLAIM = "vct";
    private static final String CREDENTIAL_ID_CLAIM = "jti";

    private final ObjectMapper objectMapper;
    private final String tokenType;
    private final String hashAlgorithm;
    private final int decoys;
    private final List<String> visibleClaims;
    protected final String issuerDid;

    // See: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request-6
    // vct sort of additional category for sd-jwt.
    private final VerifiableCredentialType vct;

    public SdJwtCredentialBuilder(
            ObjectMapper objectMapper,
            String algorithmType,
            String tokenType,
            String hashAlgorithm,
            String issuerDid,
            int decoys,
            List<String> visibleClaims,
            VerifiableCredentialType credentialType,
            CredentialConfigId vcConfigId) {
        this.objectMapper = objectMapper;
        this.issuerDid = issuerDid;
        this.tokenType = tokenType;
        this.hashAlgorithm = hashAlgorithm;
        this.decoys = decoys;
        this.visibleClaims = visibleClaims;
        this.vct = credentialType;

        // If a config id is defined, a vct must be defined.
        // Also validated in: org.keycloak.protocol.oid4vc.issuance.signing.SdJwtSigningServiceProviderFactory.validateSpecificConfiguration
        if (vcConfigId != null && this.vct == null) {
            throw new CredentialBuilderException(String.format("Missing vct for credential config id %s.", vcConfigId));
        }

        LOGGER.debugf("Successfully initiated the SD-JWT Signing Service with algorithm %s.", algorithmType);
    }

    @Override
    public CredentialBody.SdJwtCredentialBody buildCredentialBody(VCIssuanceContext vcIssuanceContext)
            throws CredentialBuilderException {

        VerifiableCredential verifiableCredential = vcIssuanceContext.getVerifiableCredential();
        DisclosureSpec.Builder disclosureSpecBuilder = DisclosureSpec.builder();
        CredentialSubject credentialSubject = verifiableCredential.getCredentialSubject();
        JsonNode claimSet = objectMapper.valueToTree(credentialSubject);

        // put all claims into the disclosure spec, except the one to be kept visible
        credentialSubject.getClaims()
                .entrySet()
                .stream()
                .filter(entry -> !visibleClaims.contains(entry.getKey()))
                .forEach(entry -> {
                    if (entry instanceof List<?> listValue) {
                        IntStream.range(0, listValue.size())
                                .forEach(i -> disclosureSpecBuilder.withUndisclosedArrayElt(entry.getKey(), i, SdJwtUtils.randomSalt()));
                    } else {
                        disclosureSpecBuilder.withUndisclosedClaim(entry.getKey(), SdJwtUtils.randomSalt());
                    }
                });

        // add the configured number of decoys
        if (decoys != 0) {
            IntStream.range(0, decoys)
                    .forEach(i -> disclosureSpecBuilder.withDecoyClaim(SdJwtUtils.randomSalt()));
        }

        ObjectNode rootNode = claimSet.withObject("");
        rootNode.put(ISSUER_CLAIM, issuerDid);

        // nbf, iat and exp are all optional. So need to be set by a protocol mapper if needed
        // see: https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-03.html#name-registered-jwt-claims

        // Use vct as type for sd-jwt.
        rootNode.put(VERIFIABLE_CREDENTIAL_TYPE_CLAIM, vct.getValue());
        rootNode.put(CREDENTIAL_ID_CLAIM, CredentialBuilderUtils.createCredentialId(verifiableCredential));

        var sdJwtBuilder = SdJwt.builder()
                .withDisclosureSpec(disclosureSpecBuilder.build())
                .withClaimSet(claimSet)
                .withHashAlgorithm(hashAlgorithm)
                .withJwsType(tokenType);

        return new CredentialBody.SdJwtCredentialBody(sdJwtBuilder);
    }
}
