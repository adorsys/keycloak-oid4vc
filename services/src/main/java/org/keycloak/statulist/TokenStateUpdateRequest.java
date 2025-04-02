package org.keycloak.statulist;

import com.fasterxml.jackson.annotation.JsonProperty; /**
 * Request class for token state update operations
 */
public class TokenStateUpdateRequest {
    @JsonProperty("tokenId")
    private String tokenId;

    @JsonProperty("action")
    private String action;

    @JsonProperty("reason")
    private String reason;

    public String getTokenId() { return tokenId; }
    public void setTokenId(String tokenId) { this.tokenId = tokenId; }

    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
}
