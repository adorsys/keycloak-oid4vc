package org.keycloak.protocol.oid4vc.issuance.credentials;

import org.keycloak.sdjwt.SdJwt;

public sealed class CredentialBody permits CredentialBody.SdJwtCredentialBody {

    private CredentialBody() {
        // private constructor to prevent external subclassing
    }

    public static final class SdJwtCredentialBody extends CredentialBody {
        private final SdJwt.Builder sdJwtBuilder;

        public SdJwtCredentialBody(SdJwt.Builder sdJwtBuilder) {
            this.sdJwtBuilder = sdJwtBuilder;
        }

        public SdJwt.Builder getBuilder() {
            return sdJwtBuilder;
        }
    }
}
