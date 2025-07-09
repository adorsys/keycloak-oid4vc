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

package org.keycloak.protocol.oid4vc.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Key attestation requirements on key storage and user authentication's attack resistance.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 * @see <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-15.html#name-credential-issuer-metadata-p">
 * Credential Issuer Metadata Parameters</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class KeyAttestationsRequired {

    @JsonProperty("key_storage")
    private List<ISO18045ResistanceLevel> keyStorage;

    @JsonProperty("user_authentication")
    private List<ISO18045ResistanceLevel> userAuthentication;

    public List<ISO18045ResistanceLevel> getKeyStorage() {
        return keyStorage;
    }

    public KeyAttestationsRequired setKeyStorage(List<ISO18045ResistanceLevel> keyStorage) {
        this.keyStorage = keyStorage;
        return this;
    }

    public List<ISO18045ResistanceLevel> getUserAuthentication() {
        return userAuthentication;
    }

    public KeyAttestationsRequired setUserAuthentication(List<ISO18045ResistanceLevel> userAuthentication) {
        this.userAuthentication = userAuthentication;
        return this;
    }
}
