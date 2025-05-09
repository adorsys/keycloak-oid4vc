package org.keycloak.protocol.oid4vc.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jboss.logging.Logger;

import java.util.List;

/**
 * Represent a batch credential request containing multiple credential request,
 * as per OID4VCI 15
 * @author <a href="mailto:Bertrand.Ogen@adorsys.com">Bertrand Ogen</a>
 */
public class BatchCredentialRequest {

    @JsonProperty("credential_requests")
    private List<CredentialRequest> credentialRequests;

    public List<CredentialRequest> getCredentialRequests() {
        return credentialRequests;
    }

    public BatchCredentialRequest setCredentialRequests(List<CredentialRequest> credentialRequests) {
        this.credentialRequests = credentialRequests;
        return this;
    }
}
