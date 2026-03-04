package org.keycloak.protocol.oid4vc.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import org.keycloak.protocol.oid4vc.issuance.credentialoffer.CredentialOfferState;

import java.util.List;

/**
 * Non-sensitive fields a pre-authorized code representation may embed.
 * <p></p>
 * Mainly intended to be used as a partial, public view of {@link CredentialOfferState}.
 */
public class PreAuthCodeCtx {

    @JsonProperty("credential_configuration_ids")
    private List<String> credentialConfigurationIds;

    @JsonProperty("authorization_details")
    private OID4VCAuthorizationDetail authorizationDetails;

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("user_id")
    private String userId;

    @JsonProperty("nonce")
    private String nonce;

    @JsonIgnore
    private long expiresAt;

    public List<String> getCredentialConfigurationIds() {
        return credentialConfigurationIds;
    }

    public PreAuthCodeCtx setCredentialConfigurationIds(List<String> credentialConfigurationIds) {
        this.credentialConfigurationIds = credentialConfigurationIds;
        return this;
    }

    public OID4VCAuthorizationDetail getAuthorizationDetails() {
        return authorizationDetails;
    }

    public PreAuthCodeCtx setAuthorizationDetails(OID4VCAuthorizationDetail authorizationDetails) {
        this.authorizationDetails = authorizationDetails;
        return this;
    }

    public String getClientId() {
        return clientId;
    }

    public PreAuthCodeCtx setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public String getUserId() {
        return userId;
    }

    public PreAuthCodeCtx setUserId(String userId) {
        this.userId = userId;
        return this;
    }

    public String getNonce() {
        return nonce;
    }

    public PreAuthCodeCtx setNonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    public long getExpiresAt() {
        return expiresAt;
    }

    public PreAuthCodeCtx setExpiresAt(long expiresAt) {
        this.expiresAt = expiresAt;
        return this;
    }
}
