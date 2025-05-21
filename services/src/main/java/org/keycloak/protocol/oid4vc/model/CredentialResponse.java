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

import java.util.List;
import java.util.stream.Collectors;

/**
 * Represents a CredentialResponse according to the OID4VCI Spec
 * {@see https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-response}
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CredentialResponse {

    public static class CredentialEntry {
        private String format;
        private Object credential;

        public String getFormat() {
            return format;
        }

        public CredentialEntry setFormat(String format) {
            this.format = format;
            return this;
        }

        public Object getCredential() {
            return credential;
        }

        public CredentialEntry setCredential(Object credential) {
            this.credential = credential;
            return this;
        }
    }

    @JsonProperty("credentials")
    private List<CredentialEntry> credentials;

    public List<CredentialEntry> getCredentials() {
        return credentials;
    }

    public CredentialResponse setCredentials(List<CredentialEntry> credentials) {
        this.credentials = credentials;
        return this;
    }

    // Backward compatibility for single credential
    public List<Object> getCredential() {
        return credentials != null
                ? credentials.stream().map(CredentialEntry::getCredential).collect(Collectors.toList())
                : null;
    }

    public CredentialResponse setCredential(List<Object> credentials) {
        this.credentials = credentials != null
                ? credentials.stream()
                .map(cred -> new CredentialEntry().setCredential(cred))
                .collect(Collectors.toList())
                : null;
        return this;
    }
}
