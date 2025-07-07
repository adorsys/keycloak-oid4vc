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

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Represents an authorization_details object in the Token Response as per OID4VCI.
 */
public class AuthorizationDetailResponse {

    @JsonProperty("type")
    private String type;

    @JsonProperty("credential_configuration_id")
    private String credentialConfigurationId;

    @JsonProperty("format")
    private String format;

    @JsonProperty("vct")
    private String vct;

    @JsonProperty("credential_identifiers")
    private List<String> credentialIdentifiers;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getCredentialConfigurationId() {
        return credentialConfigurationId;
    }

    public void setCredentialConfigurationId(String credentialConfigurationId) {
        this.credentialConfigurationId = credentialConfigurationId;
    }

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public String getVct() {
        return vct;
    }

    public void setVct(String vct) {
        this.vct = vct;
    }

    public List<String> getCredentialIdentifiers() {
        return credentialIdentifiers;
    }

    public void setCredentialIdentifiers(List<String> credentialIdentifiers) {
        this.credentialIdentifiers = credentialIdentifiers;
    }
}
