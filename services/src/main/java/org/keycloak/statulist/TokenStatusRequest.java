package org.keycloak.statulist;

import com.fasterxml.jackson.annotation.JsonProperty; /**
 * Request class for token status operations
 */
public class TokenStatusRequest {
    @JsonProperty("tokenId")
    private String tokenId;

    @JsonProperty("status")
    private String status;

    @JsonProperty("metadata")
    private Object metadata;

    public TokenStatusRequest() {}

    public TokenStatusRequest(String tokenId, String status, Object metadata) {
        this.tokenId = tokenId;
        this.status = status;
        this.metadata = metadata;
    }

    public String getTokenId() { return tokenId; }
    public void setTokenId(String tokenId) { this.tokenId = tokenId; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public Object getMetadata() { return metadata; }
    public void setMetadata(Object metadata) { this.metadata = metadata; }
}
