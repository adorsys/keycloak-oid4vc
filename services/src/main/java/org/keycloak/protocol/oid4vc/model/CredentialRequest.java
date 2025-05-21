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

package org.keycloak.protocol.oid4vc.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import java.util.List;

/**
 * Represents a CredentialRequest according to OID4VCI
 * {@see https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request}
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CredentialRequest {

    @JsonProperty("credential_specs")
    private List<CredentialSpec> credentialSpecs;

    // Backward compatibility fields for single credential requests
    private String format;

    @JsonProperty("credential_identifier")
    private String credentialIdentifier;

    @JsonProperty("proof")
    @JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "proof_type")
    @JsonSubTypes({
            @JsonSubTypes.Type(value = JwtProof.class, name = ProofType.JWT),
            @JsonSubTypes.Type(value = LdpVpProof.class, name = ProofType.LD_PROOF)
    })
    private List<Proof> proofs;

    // I have the choice of either defining format specific fields here, or adding a generic structure,
    // opening room for spamming the server. I will prefer having format specific fields.
    private String vct;

    // See: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-format-identifier-3
    @JsonProperty("credential_definition")
    private CredentialDefinition credentialDefinition;

    // New class to represent a single credential specification
    public static class CredentialSpec {
        private String format;

        @JsonProperty("credential_identifier")
        private String credentialIdentifier;

        private String vct;

        @JsonProperty("credential_definition")
        private CredentialDefinition credentialDefinition;

        @JsonProperty("proof")
        @JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "proof_type")
        @JsonSubTypes({
                @JsonSubTypes.Type(value = JwtProof.class, name = ProofType.JWT),
                @JsonSubTypes.Type(value = LdpVpProof.class, name = ProofType.LD_PROOF)
        })
        private Proof proof;

        public String getFormat() {
            return format;
        }

        public CredentialSpec setFormat(String format) {
            this.format = format;
            return this;
        }

        public String getCredentialIdentifier() {
            return credentialIdentifier;
        }

        public CredentialSpec setCredentialIdentifier(String credentialIdentifier) {
            this.credentialIdentifier = credentialIdentifier;
            return this;
        }

        public String getVct() {
            return vct;
        }

        public CredentialSpec setVct(String vct) {
            this.vct = vct;
            return this;
        }

        public CredentialDefinition getCredentialDefinition() {
            return credentialDefinition;
        }

        public CredentialSpec setCredentialDefinition(CredentialDefinition credentialDefinition) {
            this.credentialDefinition = credentialDefinition;
            return this;
        }

        public Proof getProof() {
            return proof;
        }

        public CredentialSpec setProof(Proof proof) {
            this.proof = proof;
            return this;
        }
    }

    public List<CredentialSpec> getCredentialSpecs() {
        return credentialSpecs;
    }

    public CredentialRequest setCredentialSpecs(List<CredentialSpec> credentialSpecs) {
        this.credentialSpecs = credentialSpecs;
        return this;
    }

    public String getFormat() {
        return format;
    }

    public CredentialRequest setFormat(String format) {
        this.format = format;
        return this;
    }

    public String getCredentialIdentifier() {
        return credentialIdentifier;
    }

    public CredentialRequest setCredentialIdentifier(String credentialIdentifier) {
        this.credentialIdentifier = credentialIdentifier;
        return this;
    }

    // Backward compatibility for single proof, ensuring only one proof is used for single credential requests
    public Proof getProof() {
        if (proofs != null && proofs.size() > 1) {
            throw new IllegalStateException("Multiple proofs are not supported for single credential requests in backward compatibility mode");
        }
        return proofs != null && !proofs.isEmpty() ? proofs.get(0) : null;
    }

    public CredentialRequest setProof(Proof proof) {
        if (proof != null && this.proofs != null && !this.proofs.isEmpty()) {
            throw new IllegalStateException("Cannot set single proof when proofs list is already set");
        }
        this.proofs = proof != null ? List.of(proof) : null;
        return this;
    }

    public String getVct() {
        return vct;
    }

    public CredentialRequest setVct(String vct) {
        this.vct = vct;
        return this;
    }

    public CredentialDefinition getCredentialDefinition() {
        return credentialDefinition;
    }

    public CredentialRequest setCredentialDefinition(CredentialDefinition credentialDefinition) {
        this.credentialDefinition = credentialDefinition;
        return this;
    }
}
