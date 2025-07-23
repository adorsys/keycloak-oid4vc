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

package org.keycloak.protocol.oid4vc.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationDefinition;

/**
 * Request object payload for OpenID4VP Authorization Request.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#name-authorization-request">
 * Authorization Request</a>
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class RequestObject {

    @JsonProperty("state")
    private String state;

    @JsonProperty("response_type")
    private ResponseType responseType;

    @JsonProperty("response_mode")
    private ResponseMode responseMode;

    @JsonProperty("redirect_uri")
    private String redirectUri;

    @JsonProperty("response_uri")
    private String responseUri;

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("client_id_scheme")
    private ClientIdScheme clientIdScheme;

    @JsonProperty("aud")
    private String aud;

    @JsonProperty("iss")
    private String iss;

    @JsonProperty("exp")
    private String exp;

    @JsonProperty("iat")
    private String iat;

    @JsonProperty("nonce")
    private String nonce;

    @JsonProperty("scope")
    private String scope;

    @JsonProperty("presentation_definition")
    private PresentationDefinition presentationDefinition;

    @JsonProperty("client_metadata")
    private ClientMetadata clientMetadata;
}
