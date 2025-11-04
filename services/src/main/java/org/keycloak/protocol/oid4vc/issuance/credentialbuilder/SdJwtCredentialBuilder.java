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

import org.keycloak.protocol.oid4vc.model.CredentialBuildConfig;
import org.keycloak.protocol.oid4vc.model.CredentialSubject;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.sdjwt.DisclosureSpec;
import org.keycloak.sdjwt.SdJwt;
import org.keycloak.sdjwt.SdJwtUtils;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.IntStream;

public class SdJwtCredentialBuilder implements CredentialBuilder {

    public static final String ISSUER_CLAIM = "iss";
    public static final String VERIFIABLE_CREDENTIAL_TYPE_CLAIM = "vct";

    public SdJwtCredentialBuilder() {
    }

    @Override
    public String getSupportedFormat() {
        return Format.SD_JWT_VC;
    }

    @Override
    public SdJwtCredentialBody buildCredentialBody(
            VerifiableCredential verifiableCredential,
            CredentialBuildConfig credentialBuildConfig
    ) throws CredentialBuilderException {
        // Retrieve claims
        CredentialSubject credentialSubject = verifiableCredential.getCredentialSubject();
        Map<String, Object> claimSet = credentialSubject.getClaims();

        // Put all claims into the disclosure spec, except the one to be kept visible
        DisclosureSpec.Builder disclosureSpecBuilder = DisclosureSpec.builder();
        claimSet.entrySet()
                .stream()
                .filter(entry -> !credentialBuildConfig.getSdJwtVisibleClaims().contains(entry.getKey()))
                .forEach(entry -> {
                    if (entry instanceof List<?> listValue) {
                        // FIXME: Unreachable branch. The intent was probably to check `entry.getValue()`,
                        //  but changing just that will expose the array field name and break many tests.
                        //  Needs further discussion on the wanted behavior.

                        IntStream.range(0, listValue.size())
                                .forEach(i -> disclosureSpecBuilder
                                        .withUndisclosedArrayElt(entry.getKey(), i, SdJwtUtils.randomSalt())
                                );
                    } else {
                        disclosureSpecBuilder.withUndisclosedClaim(entry.getKey(), SdJwtUtils.randomSalt());
                    }
                });

        // Populate configured fields (necessarily visible)
        claimSet.put(ISSUER_CLAIM, credentialBuildConfig.getCredentialIssuer());
        claimSet.put(VERIFIABLE_CREDENTIAL_TYPE_CLAIM, credentialBuildConfig.getCredentialType());

        // jti, nbf, iat and exp are all optional per spec.
        // see: https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-03.html#name-registered-jwt-claims
        // exp is automatically set from credential scope configuration (or can be set by protocol mapper).
        // If expirationDate is set on the VerifiableCredential, we add exp claim to the JWT.
        Optional.ofNullable(verifiableCredential.getExpirationDate())
                .map(Instant::getEpochSecond)
                .ifPresent(exp -> claimSet.put("exp", exp));

        // Normalize numeric values in nested maps (e.g., status list idx should be integer, not string)
        normalizeNumericValues(claimSet);

        // Add the configured number of decoys
        if (credentialBuildConfig.getNumberOfDecoys() > 0) {
            IntStream.range(0, credentialBuildConfig.getNumberOfDecoys())
                    .forEach(i -> disclosureSpecBuilder.withDecoyClaim(SdJwtUtils.randomSalt()));
        }

        var sdJwtBuilder = SdJwt.builder()
                .withDisclosureSpec(disclosureSpecBuilder.build())
                .withHashAlgorithm(credentialBuildConfig.getHashAlgorithm())
                .withJwsType(credentialBuildConfig.getTokenJwsType());

        return new SdJwtCredentialBody(sdJwtBuilder, claimSet);
    }

    /**
     * Normalizes numeric values in nested map structures to ensure proper JSON serialization.
     * Specifically converts string numbers to integers only for idx field as required by the spec.
     * This recursively processes nested maps and lists to handle structures like status.status_list.idx.
     *
     * @param map the map to normalize (may contain nested maps and lists)
     */
    static void normalizeNumericValues(Map<String, Object> map) {
        if (map == null) {
            return;
        }

        // Collect keys to modify to avoid ConcurrentModificationException
        ArrayList<String> keysToModify = new ArrayList<>();

        for (Map.Entry<String, Object> entry : map.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof Map) {
                Map<String, Object> nestedMap = (Map<String, Object>) value;
                normalizeNumericValues(nestedMap);
            } else if (value instanceof List) {
                List<Object> list = (List<Object>) value;
                for (Object item : list) {
                    if (item instanceof Map) {
                        Map<String, Object> nestedMap = (Map<String, Object>) item;
                        normalizeNumericValues(nestedMap);
                    }
                }
            } else if (value instanceof String) {
                String strValue = (String) value;
                // Convert idx field from string to integer (required by spec)
                if (entry.getKey().equals("idx") && strValue.matches("^\\d+$")) {
                    keysToModify.add(entry.getKey());
                }
            }
        }

        // Apply modifications after iteration
        for (String key : keysToModify) {
            Object value = map.get(key);
            if (value instanceof String) {
                String strValue = (String) value;
                Integer intValue = Integer.parseInt(strValue);
                map.put(key, intValue);
            }
        }
    }
}
