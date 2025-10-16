/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.protocol.oid4vc.issuance.mappers;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.oid4vc.issuance.TimeClaimNormalizer;
import org.keycloak.protocol.oid4vc.model.CredentialSubject;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.provider.ProviderConfigProperty;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Normalizes time-related claims according to realm configuration.
 * <p>
 * For SD-JWT VC: writes the configured claim (iat/nbf/exp) into the claim set.
 * For JWT-VC: if claim is exp, sets VC expirationDate so the builder emits exp.
 *
 * @author <a href="mailto:Rodrick.Awambeng@adorsys.com">Rodrick Awambeng</a>
 */
public class OID4VCTimeClaimsNormalizationMapper extends OID4VCMapper {

    public static final String MAPPER_ID = "oid4vc-time-claims-normalization-mapper";

    public static final String VALUE_SOURCE = "valueSource"; // VC | COMPUTE

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty claimName = new ProviderConfigProperty();
        claimName.setName(CLAIM_NAME);
        claimName.setLabel("Time Claim Name");
        claimName.setHelpText("Which time claim to set (iat, nbf, exp)");
        claimName.setType(ProviderConfigProperty.LIST_TYPE);
        claimName.setOptions(List.of("iat", "nbf", "exp"));
        claimName.setDefaultValue("iat");
        CONFIG_PROPERTIES.add(claimName);

        ProviderConfigProperty valueSource = new ProviderConfigProperty();
        valueSource.setName(VALUE_SOURCE);
        valueSource.setLabel("Source of Value");
        valueSource.setHelpText("COMPUTE uses current time; VC uses VC issuanceDate when available");
        valueSource.setType(ProviderConfigProperty.LIST_TYPE);
        valueSource.setOptions(List.of("COMPUTE", "VC"));
        valueSource.setDefaultValue("COMPUTE");
        CONFIG_PROPERTIES.add(valueSource);
    }

    @Override
    protected List<ProviderConfigProperty> getIndividualConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public boolean includeInMetadata() {
        return Optional.ofNullable(mapperModel.getConfig().get(CredentialScopeModel.INCLUDE_IN_METADATA))
                .map(Boolean::parseBoolean)
                .orElse(false);
    }

    @Override
    public void setClaimsForCredential(VerifiableCredential verifiableCredential, UserSessionModel userSessionModel) {
        String claim = Optional.ofNullable(mapperModel.getConfig().get(CLAIM_NAME)).orElse("iat");
        String source = Optional.ofNullable(mapperModel.getConfig().get(VALUE_SOURCE)).orElse("COMPUTE");

        // Determine base instant
        Instant base = "VC".equalsIgnoreCase(source) ?
                Optional.ofNullable(verifiableCredential.getIssuanceDate()).orElse(Instant.now()) :
                Instant.now();

        // Normalize via realm configuration
        TimeClaimNormalizer normalizer = new TimeClaimNormalizer(userSessionModel.getRealm());
        Instant normalized = normalizer.normalize(base, Instant.now());

        if (Format.SD_JWT_VC.equalsIgnoreCase(format)) {
            // For SD-JWT, write top-level claim into claim set by using credentialSubject claims
            CredentialSubject subject = verifiableCredential.getCredentialSubject();
            subject.setClaims(claim, normalized.getEpochSecond());
        } else if (Format.JWT_VC.equalsIgnoreCase(format)) {
            // For JWT-VC, support exp via VC expirationDate so builder emits exp
            if ("exp".equalsIgnoreCase(claim)) {
                verifiableCredential.setExpirationDate(normalized);
            }
            // iat/nbf for JWT-VC are derived by builder; we intentionally do not set them here
        }
    }

    @Override
    public void setClaimsForSubject(Map<String, Object> claims, UserSessionModel userSessionModel) {
        // NoOp
    }

    @Override
    public String getDisplayType() {
        return "Time Claims Normalization Mapper";
    }

    @Override
    public String getHelpText() {
        return "Normalizes time claims (iat/nbf/exp) using realm-configured strategy (off/randomize/round).";
    }

    @Override
    public ProtocolMapper create(KeycloakSession session) {
        return new OID4VCTimeClaimsNormalizationMapper();
    }

    @Override
    public String getId() {
        return MAPPER_ID;
    }
}
