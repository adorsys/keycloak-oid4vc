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
package org.keycloak.sdjwt.consumer;

/**
 * Verifier's policy for consuming SD-JWT VP tokens.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtVerifierPolicy {

    /**
     * Policy for Issuer-signed JWT verification.
     */
    public static class IssuerSignedJwtVerificationPolicy {
        private final boolean validateIssuedAtClaim;
        private final boolean validateExpirationClaim;
        private final boolean validateNotBeforeClaim;

        public IssuerSignedJwtVerificationPolicy(
                boolean validateIssuedAtClaim,
                boolean validateExpirationClaim,
                boolean validateNotBeforeClaim) {
            this.validateIssuedAtClaim = validateIssuedAtClaim;
            this.validateExpirationClaim = validateExpirationClaim;
            this.validateNotBeforeClaim = validateNotBeforeClaim;
        }

        public boolean mustValidateIssuedAtClaim() {
            return validateIssuedAtClaim;
        }

        public boolean mustValidateExpirationClaim() {
            return validateExpirationClaim;
        }

        public boolean mustValidateNotBeforeClaim() {
            return validateNotBeforeClaim;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static class Builder {

            protected boolean validateIssuedAtClaim;
            protected boolean validateExpirationClaim = true;
            protected boolean validateNotBeforeClaim = true;

            public Builder withValidateIssuedAtClaim(boolean validateIssuedAtClaim) {
                this.validateIssuedAtClaim = validateIssuedAtClaim;
                return this;
            }

            public Builder withValidateExpirationClaim(boolean validateExpirationClaim) {
                this.validateExpirationClaim = validateExpirationClaim;
                return this;
            }

            public Builder withValidateNotBeforeClaim(boolean validateNotBeforeClaim) {
                this.validateNotBeforeClaim = validateNotBeforeClaim;
                return this;
            }

            public IssuerSignedJwtVerificationPolicy build() {
                return new IssuerSignedJwtVerificationPolicy(
                        validateIssuedAtClaim,
                        validateExpirationClaim,
                        validateNotBeforeClaim
                );
            }
        }
    }

    /**
     * Policy for Key Binding JWT verification.
     */
    public static class KeyBindingJwtVerificationPolicy {
        /**
         * Specifies the Verifier's policy whether to check Key Binding
         */
        private final boolean keyBindingRequired;

        /**
         * Specifies the maximum age (in seconds) of an issued Key Binding
         */
        private final int allowedMaxAge;

        /**
         * Enforces nonce for replay protection
         */
        private final String nonce;

        /**
         * Enforces audience for replay protection
         */
        private final String aud;

        private final boolean validateExpirationClaim;
        private final boolean validateNotBeforeClaim;

        public KeyBindingJwtVerificationPolicy(
                boolean keyBindingRequired,
                int allowedMaxAge,
                String nonce,
                String aud,
                boolean validateExpirationClaim,
                boolean validateNotBeforeClaim) {
            this.keyBindingRequired = keyBindingRequired;
            this.allowedMaxAge = allowedMaxAge;
            this.nonce = nonce;
            this.aud = aud;
            this.validateExpirationClaim = validateExpirationClaim;
            this.validateNotBeforeClaim = validateNotBeforeClaim;
        }

        public boolean isKeyBindingRequired() {
            return keyBindingRequired;
        }

        public int getAllowedMaxAge() {
            return allowedMaxAge;
        }

        public String getNonce() {
            return nonce;
        }

        public String getAud() {
            return aud;
        }

        public boolean mustValidateExpirationClaim() {
            return validateExpirationClaim;
        }

        public boolean mustValidateNotBeforeClaim() {
            return validateNotBeforeClaim;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static class Builder {

            protected boolean keyBindingRequired = true;
            protected int allowedMaxAge = 5 * 60;
            protected String nonce;
            protected String aud;
            protected boolean validateExpirationClaim = true;
            protected boolean validateNotBeforeClaim = true;

            public Builder withKeyBindingRequired(boolean keyBindingRequired) {
                this.keyBindingRequired = keyBindingRequired;
                return this;
            }

            public Builder withAllowedMaxAge(int allowedMaxAge) {
                this.allowedMaxAge = allowedMaxAge;
                return this;
            }

            public Builder withNonce(String nonce) {
                this.nonce = nonce;
                return this;
            }

            public Builder withAud(String aud) {
                this.aud = aud;
                return this;
            }

            public Builder withValidateExpirationClaim(boolean validateExpirationClaim) {
                this.validateExpirationClaim = validateExpirationClaim;
                return this;
            }

            public Builder withValidateNotBeforeClaim(boolean validateNotBeforeClaim) {
                this.validateNotBeforeClaim = validateNotBeforeClaim;
                return this;
            }

            public KeyBindingJwtVerificationPolicy build() {
                if (keyBindingRequired && (aud == null || nonce == null || nonce.isEmpty())) {
                    throw new IllegalArgumentException(
                            "Missing `nonce` and `aud` claims for replay protection"
                    );
                }

                return new KeyBindingJwtVerificationPolicy(
                        keyBindingRequired,
                        allowedMaxAge,
                        nonce,
                        aud,
                        validateExpirationClaim,
                        validateNotBeforeClaim
                );
            }
        }
    }
}
