package org.keycloak.statulist;

import com.fasterxml.jackson.annotation.JsonProperty; /**
 * Metadata class for suspension information
 */
public class TokenSuspensionMetadata {
    @JsonProperty("reason")
    private String reason;

    @JsonProperty("timestamp")
    private String timestamp;

    public TokenSuspensionMetadata(String reason, String timestamp) {
        this.reason = reason;
        this.timestamp = timestamp;
    }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }
}
