package org.keycloak.protocol.oid4vc.issuance.credentialbuilder;

import org.keycloak.protocol.oid4vc.model.CredentialSubject;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.protocol.oid4vc.model.VerifiableCredentialType;
import org.keycloak.sdjwt.DisclosureSpec;
import org.keycloak.sdjwt.SdJwt;
import org.keycloak.sdjwt.SdJwtUtils;

import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

public class SdJwtCredentialBuilder extends AbstractCredentialBuilder {

    private static final String ISSUER_CLAIM = "iss";
    private static final String VERIFIABLE_CREDENTIAL_TYPE_CLAIM = "vct";
    private static final String CREDENTIAL_ID_CLAIM = "jti";

    protected final String issuerDid;

    private final String tokenType;
    private final String hashAlgorithm;

    private final List<String> visibleClaims;
    private final int numberOfDecoys;

    // See: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request-6
    // vct sort of additional category for sd-jwt.
    private final VerifiableCredentialType vct;

    public SdJwtCredentialBuilder(
            String issuerDid,
            String tokenType,
            String hashAlgorithm,
            List<String> visibleClaims,
            int numberOfDecoys,
            VerifiableCredentialType credentialType) {
        this.issuerDid = issuerDid;
        this.tokenType = tokenType;
        this.hashAlgorithm = hashAlgorithm;
        this.numberOfDecoys = numberOfDecoys;
        this.visibleClaims = visibleClaims;
        this.vct = credentialType;
    }

    @Override
    public String getSupportedFormat() {
        return Format.SD_JWT_VC;
    }

    @Override
    public CredentialBody.SdJwtCredentialBody buildCredentialBody(VerifiableCredential verifiableCredential)
            throws CredentialBuilderException {
        // Retrieve claims
        CredentialSubject credentialSubject = verifiableCredential.getCredentialSubject();
        Map<String, Object> claimSet = credentialSubject.getClaims();

        // Populate configured fields
        claimSet.put(ISSUER_CLAIM, issuerDid);
        claimSet.put(VERIFIABLE_CREDENTIAL_TYPE_CLAIM, vct.getValue());
        claimSet.put(CREDENTIAL_ID_CLAIM, CredentialBuilderUtils.createCredentialId(verifiableCredential));

        // nbf, iat and exp are all optional. So need to be set by a protocol mapper if needed
        // see: https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-03.html#name-registered-jwt-claims

        // Put all claims into the disclosure spec, except the one to be kept visible
        DisclosureSpec.Builder disclosureSpecBuilder = DisclosureSpec.builder();
        credentialSubject.getClaims()
                .entrySet()
                .stream()
                .filter(entry -> !visibleClaims.contains(entry.getKey()))
                .forEach(entry -> {
                    if (entry instanceof List<?> listValue) {
                        IntStream.range(0, listValue.size())
                                .forEach(i -> disclosureSpecBuilder
                                        .withUndisclosedArrayElt(entry.getKey(), i, SdJwtUtils.randomSalt())
                                );
                    } else {
                        disclosureSpecBuilder.withUndisclosedClaim(entry.getKey(), SdJwtUtils.randomSalt());
                    }
                });

        // Add the configured number of decoys
        if (numberOfDecoys != 0) {
            IntStream.range(0, numberOfDecoys)
                    .forEach(i -> disclosureSpecBuilder.withDecoyClaim(SdJwtUtils.randomSalt()));
        }

        var sdJwtBuilder = SdJwt.builder()
                .withDisclosureSpec(disclosureSpecBuilder.build())
                .withHashAlgorithm(hashAlgorithm)
                .withJwsType(tokenType);

        return new CredentialBody.SdJwtCredentialBody(sdJwtBuilder, claimSet);
    }
}
