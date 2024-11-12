/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

/**
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtCredentialBuilderFactory implements CredentialBuilderFactory {

    @Override
    public String getId() {
        return Format.SD_JWT_VC;
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
}
