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

package org.keycloak.sdjwt;

import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.sdjwt.consumer.SdJwtVerifierPolicy;

/**
 * Options for Issuer-signed JWT verification.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class IssuerSignedJwtVerificationOpts extends SdJwtVerifierPolicy.IssuerSignedJwtVerificationPolicy {

    private final SignatureVerifierContext verifier;

    public IssuerSignedJwtVerificationOpts(
            SignatureVerifierContext verifier,
            boolean validateIssuedAtClaim,
            boolean validateExpirationClaim,
            boolean validateNotBeforeClaim) {
        super(validateIssuedAtClaim, validateExpirationClaim, validateNotBeforeClaim);
        this.verifier = verifier;
    }

    public SignatureVerifierContext getVerifier() {
        return verifier;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends SdJwtVerifierPolicy.IssuerSignedJwtVerificationPolicy.Builder {

        private SignatureVerifierContext verifier;

        public Builder withVerifier(SignatureVerifierContext verifier) {
            this.verifier = verifier;
            return this;
        }

        @Override
        public Builder withValidateIssuedAtClaim(boolean validateIssuedAtClaim) {
            super.withValidateIssuedAtClaim(validateIssuedAtClaim);
            return this;
        }

        @Override
        public Builder withValidateExpirationClaim(boolean validateExpirationClaim) {
            super.withValidateExpirationClaim(validateExpirationClaim);
            return this;
        }

        @Override
        public Builder withValidateNotBeforeClaim(boolean validateNotBeforeClaim) {
            super.withValidateNotBeforeClaim(validateNotBeforeClaim);
            return this;
        }

        @Override
        public IssuerSignedJwtVerificationOpts build() {
            return new IssuerSignedJwtVerificationOpts(
                    verifier,
                    validateIssuedAtClaim,
                    validateExpirationClaim,
                    validateNotBeforeClaim
            );
        }
    }
}
