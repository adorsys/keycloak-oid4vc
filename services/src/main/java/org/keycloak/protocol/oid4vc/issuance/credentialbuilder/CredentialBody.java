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

import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.sdjwt.SdJwt;

import java.util.Map;

public sealed class CredentialBody permits
        CredentialBody.LDCredentialBody,
        CredentialBody.JwtCredentialBody,
        CredentialBody.SdJwtCredentialBody {

    private CredentialBody() {
        // private constructor to prevent external subclassing
    }

    public static final class LDCredentialBody extends CredentialBody {

        private final VerifiableCredential verifiableCredential;

        public LDCredentialBody(VerifiableCredential verifiableCredential) {
            this.verifiableCredential = verifiableCredential;
        }

        public VerifiableCredential getVerifiableCredential() {
            return verifiableCredential;
        }
    }

    public static final class JwtCredentialBody extends CredentialBody {

        private final JWSBuilder.EncodingBuilder jwsEncodingBuilder;

        public JwtCredentialBody(JWSBuilder.EncodingBuilder jwsEncodingBuilder) {
            this.jwsEncodingBuilder = jwsEncodingBuilder;
        }

        public String sign(SignatureSignerContext signatureSignerContext) {
            return jwsEncodingBuilder.sign(signatureSignerContext);
        }
    }

    public static final class SdJwtCredentialBody extends CredentialBody {

        private static final String CNF_CLAIM = "cnf";

        private final SdJwt.Builder sdJwtBuilder;
        private final Map<String, Object> claimSet;

        public SdJwtCredentialBody(SdJwt.Builder sdJwtBuilder, Map<String, Object> claimSet) {
            this.sdJwtBuilder = sdJwtBuilder;
            this.claimSet = claimSet;
        }

        public void addCnfClaim(Object cnf) {
            claimSet.put(CNF_CLAIM, cnf);
        }

        public String sign(SignatureSignerContext signatureSignerContext) {
            JsonNode claimSet = CredentialBuilderUtils.mapper.valueToTree(this.claimSet);
            SdJwt sdJwt = sdJwtBuilder
                    .withClaimSet(claimSet)
                    .withSigner(signatureSignerContext)
                    .build();

            return sdJwt.toSdJwtString();
        }
    }
}
