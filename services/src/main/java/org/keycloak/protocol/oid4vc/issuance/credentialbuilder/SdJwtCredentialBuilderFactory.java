package org.keycloak.protocol.oid4vc.issuance.credentialbuilder;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.VCIssuerException;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.protocol.oid4vc.model.VerifiableCredentialType;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.keycloak.protocol.oid4vc.issuance.signing.VCSigningServiceProviderFactory.ISSUER_DID_REALM_ATTRIBUTE_KEY;

public class SdJwtCredentialBuilderFactory implements CredentialBuilderFactory {

    @Override
    public String getId() {
        return Format.SD_JWT_VC;
    }

    @Override
    public CredentialBuilder create(KeycloakSession session, ComponentModel model) {
        String issuerDid = Optional.ofNullable(
                        session
                                .getContext()
                                .getRealm()
                                .getAttribute(ISSUER_DID_REALM_ATTRIBUTE_KEY))
                .orElseThrow(() -> new VCIssuerException("No issuerDid configured."));

        String tokenType = model.get(CredentialBuilderProperties.TOKEN_TYPE.getKey());
        String hashAlgorithm = model.get(CredentialBuilderProperties.HASH_ALGORITHM.getKey());
        int numberOfDecoys = Integer.parseInt(model.get(CredentialBuilderProperties.DECOYS.getKey()));

        List<String> visibleClaims = Optional.ofNullable(model.get(CredentialBuilderProperties.VISIBLE_CLAIMS.getKey()))
                .map(vsbleClaims -> vsbleClaims.split(","))
                .map(Arrays::asList)
                .orElse(List.of());

        String vct = model.get(CredentialBuilderProperties.VC_VCT.getKey());
        String vcConfigId = model.get(CredentialBuilderProperties.VC_CONFIG_ID.getKey());

        // Validate that if a config id is defined, a vct must be defined.
        if (vcConfigId != null && vct == null) {
            throw new CredentialBuilderException(String.format("Missing vct for credential config id %s.", vcConfigId));
        }

        return new SdJwtCredentialBuilder(
                issuerDid,
                tokenType,
                hashAlgorithm,
                visibleClaims,
                numberOfDecoys,
                VerifiableCredentialType.from(vct)
        );
    }

    @Override
    public String getHelpText() {
        return null;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }
}
