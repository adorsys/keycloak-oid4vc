package org.keycloak.protocol.oid4vc.issuance.credentialbuilder;

import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.sdjwt.SdJwt;

import java.util.Map;

public sealed class CredentialBody permits CredentialBody.SdJwtCredentialBody {

    private CredentialBody() {
        // private constructor to prevent external subclassing
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

        public SdJwt build(SignatureSignerContext signatureSignerContext) {
            JsonNode claimSet = CredentialBuilderUtils.mapper.valueToTree(this.claimSet);

            return sdJwtBuilder
                    .withClaimSet(claimSet)
                    .withSigner(signatureSignerContext)
                    .build();
        }
    }
}
