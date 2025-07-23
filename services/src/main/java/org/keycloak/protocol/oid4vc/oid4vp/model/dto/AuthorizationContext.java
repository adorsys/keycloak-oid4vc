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

package org.keycloak.protocol.oid4vc.oid4vp.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Data context for an OpenID4VP authorization session.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthorizationContext {

    /**
     * The authorization request as a link.
     * In cross-device flows, a QR code is generated from this link.
     */
    @JsonProperty(value = "authorization_request")
    private String authorizationRequest;

    /**
     * The transaction ID associated with the authorization request.
     * Use this ID to inquire the status of any response to the request.
     * Must not be known beyond the authenticating party.
     */
    @JsonProperty(value = "transaction_id")
    private String transactionId;

    /**
     * The request ID associated with the authorization request.
     * Unlike the transaction ID, it should not enable status inquiries.
     * Matches the state parameter in the request object.
     */
    @JsonProperty(value = "request_id")
    private String requestId;

    /**
     * The request object as a JWT.
     */
    @JsonProperty(value = "request_object_jwt")
    private String requestObjectJwt;

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public String getAuthorizationRequest() {
        return authorizationRequest;
    }

    public void setAuthorizationRequest(String authorizationRequest) {
        this.authorizationRequest = authorizationRequest;
    }

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public String getRequestObjectJwt() {
        return requestObjectJwt;
    }

    public void setRequestObjectJwt(String requestObjectJwt) {
        this.requestObjectJwt = requestObjectJwt;
    }
}
