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

import org.keycloak.protocol.oid4vc.model.CredentialConfigId;
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

/**
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtCredentialBuilder extends AbstractCredentialBuilder {

    private static final String ISSUER_CLAIM = "iss";
    private static final String VERIFIABLE_CREDENTIAL_TYPE_CLAIM = "vct";
    private static final String CREDENTIAL_ID_CLAIM = "jti";

    private final String issuerDid;
    private final CredentialConfigId vcConfigId;

    private final String tokenJwsType;
    private final String hashAlgorithm;

    private final List<String> visibleClaims;
    private final int numberOfDecoys;

    // See: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request-6
    // vct sort of additional category for sd-jwt.
    private final VerifiableCredentialType vct;

    public SdJwtCredentialBuilder(
            String issuerDid,
            String tokenJwsType,
            String hashAlgorithm,
            List<String> visibleClaims,
            int numberOfDecoys,
            VerifiableCredentialType credentialType,
            CredentialConfigId vcConfigId
    ) {
        this.issuerDid = issuerDid;
        this.tokenJwsType = tokenJwsType;
        this.hashAlgorithm = hashAlgorithm;
        this.numberOfDecoys = numberOfDecoys;
        this.visibleClaims = visibleClaims;
        this.vct = credentialType;
        this.vcConfigId = vcConfigId;
    }

    @Override
    public LocatorInfo getLocatorInfo() {
        return new LocatorInfo(Format.SD_JWT_VC, vct, vcConfigId);
    }

    @Override
    public CredentialBody.SdJwtCredentialBody buildCredentialBody(VerifiableCredential verifiableCredential)
            throws CredentialBuilderException {
        // Retrieve claims
        CredentialSubject credentialSubject = verifiableCredential.getCredentialSubject();
        Map<String, Object> claimSet = credentialSubject.getClaims();

        // Put all claims into the disclosure spec, except the one to be kept visible
        DisclosureSpec.Builder disclosureSpecBuilder = DisclosureSpec.builder();
        claimSet.entrySet()
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

        // Populate configured fields (necessarily visible)
        claimSet.put(ISSUER_CLAIM, issuerDid);
        claimSet.put(VERIFIABLE_CREDENTIAL_TYPE_CLAIM, vct.getValue());
        claimSet.put(CREDENTIAL_ID_CLAIM, CredentialBuilderUtils.createCredentialId(verifiableCredential));

        // nbf, iat and exp are all optional. So need to be set by a protocol mapper if needed
        // see: https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-03.html#name-registered-jwt-claims

        // Add the configured number of decoys
        if (numberOfDecoys > 0) {
            IntStream.range(0, numberOfDecoys)
                    .forEach(i -> disclosureSpecBuilder.withDecoyClaim(SdJwtUtils.randomSalt()));
        }

        var sdJwtBuilder = SdJwt.builder()
                .withDisclosureSpec(disclosureSpecBuilder.build())
                .withHashAlgorithm(hashAlgorithm)
                .withJwsType(tokenJwsType);

        return new CredentialBody.SdJwtCredentialBody(sdJwtBuilder, claimSet);
    }
}
