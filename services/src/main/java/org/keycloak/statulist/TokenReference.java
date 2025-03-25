package org.keycloak.statulist;

// TokenReference class to store token mappings
public class TokenReference {
    private final String tokenId;
    private final String referenceToken;

    public TokenReference(String tokenId, String referenceToken) {
        this.tokenId = tokenId;
        this.referenceToken = referenceToken;
    }

    public String getTokenId() {
        return tokenId;
    }

    public String getReferenceToken() {
        return referenceToken;
    }
}
