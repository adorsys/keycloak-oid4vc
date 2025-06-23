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

/**
 * Represents an attestation proof for Credential Request in OID4VCI (Section 8.2.1.1).
 * This is used for the "attestation" proof type, as per the OpenID4VCI specification.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-attestation-proof-type">OID4VCI Attestation Proof Type</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AttestationProof implements Proof {

    @JsonProperty("attestation")
    private String attestation;

    public AttestationProof() {}

    public AttestationProof(String attestation) {
        this.attestation = attestation;
    }

    @Override
    public String getProofType() {
        return ProofType.ATTESTATION;
    }

    public String getAttestation() {
        return attestation;
    }

    public AttestationProof setAttestation(String attestation) {
        this.attestation = attestation;
        return this;
    }
} 