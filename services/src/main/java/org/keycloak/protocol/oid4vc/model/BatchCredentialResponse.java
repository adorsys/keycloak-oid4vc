package org.keycloak.protocol.oid4vc.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Represents a batch credential response containing multiple credential or a transaction_id,
 * as per OID4VCI draft 15.
 * @author <a href="mailto:Bertrand.Ogen@adorsys.com">Bertrand Ogen</a>
 */
public class BatchCredentialResponse {
    @JsonProperty("credentials")
    private List<CredentialResponse> credentials;

    @JsonProperty("notification_id")
    private String notificationId;

    @JsonProperty("transaction_id")
    private String transactionId;

    public List<CredentialResponse> getCredentials() {
        return credentials;
    }

    public BatchCredentialResponse setCredentials(List<CredentialResponse> credentials) {
        this.credentials = credentials;
        return this;
    }

    public String getNotificationId() {
        return notificationId;
    }

    public BatchCredentialResponse setNotificationId(String notificationId) {
        this.notificationId = notificationId;
        return this;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public BatchCredentialResponse setTransactionId(String transactionId) {
        this.transactionId = transactionId;
        return this;
    }
}
