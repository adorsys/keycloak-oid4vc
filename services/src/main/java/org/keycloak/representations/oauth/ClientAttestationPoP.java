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
 * Client Attestation Proof of Possession JWT as defined in draft-ietf-oauth-attestation-based-client-auth-07
 *
 * @author <a href="mailto:Forkim.Akwichek@adorsys.com">Forkim Akwichek</a>
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html">OAuth 2.0 Attestation-Based Client Authentication</a>
 */
public class ClientAttestationPoP extends JsonWebToken {

    public static final String TYPE = "oauth-client-attestation-pop+jwt";

    @JsonProperty("challenge")
    private String challenge;

    public String getChallenge() {
        return challenge;
    }

    public void setChallenge(String challenge) {
        this.challenge = challenge;
    }

    public String getIssuer() {
        return super.getIssuer();
    }

    public Long getIssuedAt() {
        return super.getIat();
    }

    public boolean isActive(int clockSkew) {
        return super.isActive(clockSkew);
    }

    public Long getNotBefore() {
        return super.getNbf();
    }

    public String[] getAudience() {
        return super.getAudience();
    }

    public boolean hasAudience(String audience) {
        return super.hasAudience(audience);
    }

    public String getId() {
        return super.getId();
    }
}
