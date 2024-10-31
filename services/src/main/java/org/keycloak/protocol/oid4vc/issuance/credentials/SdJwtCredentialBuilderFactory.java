package org.keycloak.protocol.oid4vc.issuance.credentials;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.VCIssuerException;
import org.keycloak.protocol.oid4vc.model.CredentialConfigId;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.protocol.oid4vc.model.VerifiableCredentialType;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.keycloak.protocol.oid4vc.issuance.signing.VCSigningServiceProviderFactory.ISSUER_DID_REALM_ATTRIBUTE_KEY;

public class SdJwtCredentialBuilderFactory implements CredentialBuilderFactory {

    @Override
    public CredentialBuilder create(KeycloakSession session, ComponentModel model) {
        String algorithmType = model.get(CredentialBuilderProperties.ALGORITHM_TYPE.getKey());
        String tokenType = model.get(CredentialBuilderProperties.TOKEN_TYPE.getKey());
        String hashAlgorithm = model.get(CredentialBuilderProperties.HASH_ALGORITHM.getKey());
        int decoys = Integer.parseInt(model.get(CredentialBuilderProperties.DECOYS.getKey()));
        // Store vct as a conditional attribute of the signing service.
        // But is vcConfigId is provided, vct must be provided as well.
        String vct = model.get(CredentialBuilderProperties.VC_VCT.getKey());
        String vcConfigId = model.get(CredentialBuilderProperties.VC_CONFIG_ID.getKey());

        List<String> visibleClaims = Optional.ofNullable(model.get(CredentialBuilderProperties.VISIBLE_CLAIMS.getKey()))
                .map(vsbleClaims -> vsbleClaims.split(","))
                .map(Arrays::asList)
                .orElse(List.of());

        String issuerDid = Optional.ofNullable(
                        session
                                .getContext()
                                .getRealm()
                                .getAttribute(ISSUER_DID_REALM_ATTRIBUTE_KEY))
                .orElseThrow(() -> new VCIssuerException("No issuerDid configured."));

        return new SdJwtCredentialBuilder(
                new ObjectMapper(),
                algorithmType,
                tokenType,
                hashAlgorithm,
                issuerDid,
                decoys,
                visibleClaims,
                VerifiableCredentialType.from(vct),
                CredentialConfigId.from(vcConfigId)
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

    @Override
    public String getId() {
        return Format.SD_JWT_VC;
    }
}
