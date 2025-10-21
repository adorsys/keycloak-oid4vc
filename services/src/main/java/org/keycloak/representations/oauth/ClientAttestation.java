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

package org.keycloak.representations.oauth;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.representations.JsonWebToken;

/**
 * Client Attestation JWT as defined in draft-ietf-oauth-attestation-based-client-auth-07
 *
 * @author <a href="mailto:Forkim.Akwichek@adorsys.com">Forkim Akwichek</a>
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html">OAuth 2.0 Attestation-Based Client Authentication</a>
 */
public class ClientAttestation extends JsonWebToken {

    public static final String TYPE = "oauth-client-attestation+jwt";

    @JsonProperty("cnf")
    private Confirmation confirmation;

    public Confirmation getConfirmation() {
        return confirmation;
    }

    public void setConfirmation(Confirmation confirmation) {
        this.confirmation = confirmation;
    }

    public String getSubject() {
        return super.getSubject();
    }

    public String getIssuer() {
        return super.getIssuer();
    }

    public Long getExp() {
        return super.getExp();
    }

    public boolean isActive(int clockSkew) {
        return super.isActive(clockSkew);
    }

    public Long getNotBefore() {
        return super.getNbf();
    }

    public static class Confirmation {
        @JsonProperty("jwk")
        private Object jwk;

        public Object getJwk() {
            return jwk;
        }

        public void setJwk(Object jwk) {
            this.jwk = jwk;
        }
    }
}
