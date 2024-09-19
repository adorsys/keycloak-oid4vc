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

package org.keycloak.sdjwt.vp;

import org.keycloak.sdjwt.consumer.SdJwtVerifierPolicy;

/**
 * Options for Key Binding JWT verification.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class KeyBindingJwtVerificationOpts extends SdJwtVerifierPolicy.KeyBindingJwtVerificationPolicy {

    public KeyBindingJwtVerificationOpts(
            boolean keyBindingRequired,
            int allowedMaxAge,
            String nonce,
            String aud,
            boolean validateExpirationClaim,
            boolean validateNotBeforeClaim) {
        super(keyBindingRequired, allowedMaxAge, nonce, aud, validateExpirationClaim, validateNotBeforeClaim);
    }

    public static KeyBindingJwtVerificationOpts.Builder builder() {
        return new KeyBindingJwtVerificationOpts.Builder();
    }

    public static class Builder extends SdJwtVerifierPolicy.KeyBindingJwtVerificationPolicy.Builder {

        public Builder withKeyBindingRequired(boolean keyBindingRequired) {
            super.withKeyBindingRequired(keyBindingRequired);
            return this;
        }

        public Builder withAllowedMaxAge(int allowedMaxAge) {
            super.withAllowedMaxAge(allowedMaxAge);
            return this;
        }

        public Builder withNonce(String nonce) {
            super.withNonce(nonce);
            return this;
        }

        public Builder withAud(String aud) {
            super.withAud(aud);
            return this;
        }

        public Builder withValidateExpirationClaim(boolean validateExpirationClaim) {
            super.withValidateExpirationClaim(validateExpirationClaim);
            return this;
        }

        public Builder withValidateNotBeforeClaim(boolean validateNotBeforeClaim) {
            super.withValidateNotBeforeClaim(validateNotBeforeClaim);
            return this;
        }

        public KeyBindingJwtVerificationOpts build() {
            return (KeyBindingJwtVerificationOpts) super.build();
        }
    }
}
