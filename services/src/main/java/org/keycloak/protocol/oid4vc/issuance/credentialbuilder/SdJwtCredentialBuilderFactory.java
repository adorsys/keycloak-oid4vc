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
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.issuance.VCIssuerException;
import org.keycloak.protocol.oid4vc.model.CredentialConfigId;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.protocol.oid4vc.model.VerifiableCredentialType;
import org.keycloak.provider.ConfigurationValidationHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.keycloak.protocol.oid4vc.issuance.signing.VCSigningServiceProviderFactory.ISSUER_DID_REALM_ATTRIBUTE_KEY;
import static org.keycloak.provider.ProviderConfigProperty.MULTIVALUED_STRING_SEPARATOR;

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
        return "Builds verifiable credentials on the SD-JWT format";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property(CredentialBuilderProperties.TOKEN_TYPE.asConfigProperty())
                .property(CredentialBuilderProperties.HASH_ALGORITHM.asConfigProperty())
                .property(CredentialBuilderProperties.DECOYS.asConfigProperty())
                .property(CredentialBuilderProperties.VISIBLE_CLAIMS.asConfigProperty())
                .property(CredentialBuilderProperties.VC_VCT.asConfigProperty())
                .property(CredentialBuilderProperties.VC_CONFIG_ID.asConfigProperty())
                .build();
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model)
            throws ComponentValidationException {
        ConfigurationValidationHelper helper = ConfigurationValidationHelper.check(model)
                .checkRequired(CredentialBuilderProperties.TOKEN_TYPE.asConfigProperty())
                .checkRequired(CredentialBuilderProperties.HASH_ALGORITHM.asConfigProperty())
                .checkRequired(CredentialBuilderProperties.DECOYS.asConfigProperty())
                .checkRequired(CredentialBuilderProperties.VISIBLE_CLAIMS.asConfigProperty());

        // Ensure that VCT is set if VC_CONFIG_ID id is set.
        if (model.get(CredentialBuilderProperties.VC_CONFIG_ID.getKey()) != null) {
            helper.checkRequired(CredentialBuilderProperties.VC_VCT.asConfigProperty());
        }
    }

    @Override
    public CredentialBuilder create(KeycloakSession session, ComponentModel model) {
        RealmModel realm = session.getContext().getRealm();
        String issuerDid = Optional.ofNullable(realm.getAttribute(ISSUER_DID_REALM_ATTRIBUTE_KEY))
                .orElseThrow(() -> new VCIssuerException("No issuerDid configured."));

        String tokenType = model.get(CredentialBuilderProperties.TOKEN_TYPE.getKey());
        String hashAlgorithm = model.get(CredentialBuilderProperties.HASH_ALGORITHM.getKey());
        int numberOfDecoys = Integer.parseInt(model.get(CredentialBuilderProperties.DECOYS.getKey()));

        String configuredVisibleClaims = model.get(CredentialBuilderProperties.VISIBLE_CLAIMS.getKey());
        List<String> visibleClaims = Optional.ofNullable(configuredVisibleClaims)
                .map(claims -> claims.split(MULTIVALUED_STRING_SEPARATOR))
                .map(Arrays::asList)
                .orElse(List.of());

        String vct = model.get(CredentialBuilderProperties.VC_VCT.getKey());
        String vcConfigId = model.get(CredentialBuilderProperties.VC_CONFIG_ID.getKey());

        return new SdJwtCredentialBuilder(
                issuerDid,
                tokenType,
                hashAlgorithm,
                visibleClaims,
                numberOfDecoys,
                VerifiableCredentialType.from(vct),
                CredentialConfigId.from(vcConfigId)
        );
    }
}
