package org.keycloak.services.Statuslist;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import org.junit.Test;
import org.junit.Assert;
import org.keycloak.Token;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.enums.SslRequired;
import org.keycloak.component.ComponentModel;
import org.keycloak.http.HttpRequest;
import org.keycloak.http.HttpResponse;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.CibaConfig;
import org.keycloak.models.ClientInitialAccessModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientProvider;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.ClientScopeProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.GroupProvider;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.IdentityProviderStorageProvider;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.OAuth2DeviceConfig;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.ParConfig;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.RequiredActionConfigModel;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.models.RequiredCredentialModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.RoleProvider;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.ThemeManager;
import org.keycloak.models.TokenManager;
import org.keycloak.models.UserLoginFailureProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.UserSessionProvider;
import org.keycloak.models.WebAuthnPolicy;
import org.keycloak.provider.InvalidationHandler;
import org.keycloak.provider.Provider;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.statulist.StatusResourceProvider;
import org.keycloak.statulist.TokenStateUpdateRequest;
import org.keycloak.statulist.TokenStatusRequest;
import org.keycloak.urls.UrlType;
import org.keycloak.vault.VaultTranscriber;

import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

public class StatusResourceProviderTest {

    @Test
    public void testPublishTokenStatus_NullRequest() {

        KeycloakSession mockSession = createMockSession();
        StatusResourceProvider provider = new StatusResourceProvider(mockSession);

        // Act
        Response response = provider.publishTokenStatus(null);

        // Assert
        Assert.assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        Assert.assertTrue(response.getEntity().toString().contains("Token ID is required"));
    }

    @Test
    public void testPublishTokenStatus_EmptyTokenId() {
        // Setup
        KeycloakSession mockSession = createMockSession();
        StatusResourceProvider provider = new StatusResourceProvider(mockSession);
        TokenStatusRequest request = new TokenStatusRequest();
        request.setTokenId("");

        // Act
        Response response = provider.publishTokenStatus(request);

        // Assert
        Assert.assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        Assert.assertTrue(response.getEntity().toString().contains("Token ID is required"));
    }

    @Test
    public void testUpdateTokenState_InvalidAction() {
        // Setup
        KeycloakSession mockSession = createMockSession();
        StatusResourceProvider provider = new StatusResourceProvider(mockSession);
        TokenStateUpdateRequest request = new TokenStateUpdateRequest();
        request.setTokenId("test-token");
        request.setAction("invalid-action");

        // Act
        Response response = provider.updateTokenState(request);

        // Assert
        Assert.assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        Assert.assertTrue(response.getEntity().toString().contains("Invalid action"));
    }

    @Test
    public void testGetTokenStatus_NullTokenId() {
        // Setup
        KeycloakSession mockSession = createMockSession();
        StatusResourceProvider provider = new StatusResourceProvider(mockSession);

        // Act
        Response response = provider.getTokenStatus(null);

        // Assert
        Assert.assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        Assert.assertTrue(response.getEntity().toString().contains("Token ID is required"));
    }

    @Test
    public void testGetTokenStatus_validToken() {
        // Setup
        KeycloakSession mockSession = createMockSession();
        StatusResourceProvider provider = new StatusResourceProvider(mockSession);
        TokenStatusRequest request = new TokenStatusRequest();
        request.setTokenId("test-token");

        // Act
        Response response = provider.getTokenStatus(String.valueOf(request));

        // Assert
        Assert.assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        Assert.assertNotNull(response.getEntity());
    }

    @Test
    public void testPublishTokenStatus_validToken(){
        // Setup
        KeycloakSession mockSession = createMockSession();
        StatusResourceProvider provider = new StatusResourceProvider(mockSession);
        TokenStatusRequest request = new TokenStatusRequest();
        request.setTokenId("test-token");
        request.setStatus("ACTIVE");
        request.setMetadata(Map.of("key", "value"));

        // Act
        Response response = provider.publishTokenStatus(request);

        // Assert
        Assert.assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        Assert.assertNotNull(response.getEntity());
    }

    // Helper method to create a basic mock session
    private KeycloakSession createMockSession() {
        return new KeycloakSession() {
            private final KeycloakContext context = new KeycloakContext() {
                @Override
                public AuthenticationSessionModel getAuthenticationSession() {
                    return new AuthenticationSessionModel() {
                        @Override
                        public String getRedirectUri() {
                            return "";
                        }

                        @Override
                        public void setRedirectUri(String uri) {

                        }

                        @Override
                        public RealmModel getRealm() {
                            return null;
                        }

                        @Override
                        public ClientModel getClient() {
                            return null;
                        }

                        @Override
                        public String getAction() {
                            return "";
                        }

                        @Override
                        public void setAction(String action) {

                        }

                        @Override
                        public String getProtocol() {
                            return "";
                        }

                        @Override
                        public void setProtocol(String method) {

                        }

                        @Override
                        public String getTabId() {
                            return "";
                        }

                        @Override
                        public RootAuthenticationSessionModel getParentSession() {
                            return null;
                        }

                        @Override
                        public Map<String, ExecutionStatus> getExecutionStatus() {
                            return Map.of();
                        }

                        @Override
                        public void setExecutionStatus(String authenticator, ExecutionStatus status) {

                        }

                        @Override
                        public void clearExecutionStatus() {

                        }

                        @Override
                        public UserModel getAuthenticatedUser() {
                            return new UserModel() {
                                @Override
                                public String getId() {
                                    return "";
                                }

                                @Override
                                public String getUsername() {
                                    return "";
                                }

                                @Override
                                public void setUsername(String username) {

                                }

                                @Override
                                public Long getCreatedTimestamp() {
                                    return 0L;
                                }

                                @Override
                                public void setCreatedTimestamp(Long timestamp) {

                                }

                                @Override
                                public boolean isEnabled() {
                                    return false;
                                }

                                @Override
                                public void setEnabled(boolean enabled) {

                                }

                                @Override
                                public void setSingleAttribute(String name, String value) {

                                }

                                @Override
                                public void setAttribute(String name, List<String> values) {

                                }

                                @Override
                                public void removeAttribute(String name) {

                                }

                                @Override
                                public String getFirstAttribute(String name) {
                                    return "";
                                }

                                @Override
                                public Stream<String> getAttributeStream(String name) {
                                    return Stream.empty();
                                }

                                @Override
                                public Map<String, List<String>> getAttributes() {
                                    return Map.of();
                                }

                                @Override
                                public Stream<String> getRequiredActionsStream() {
                                    return Stream.empty();
                                }

                                @Override
                                public void addRequiredAction(String action) {

                                }

                                @Override
                                public void removeRequiredAction(String action) {

                                }

                                @Override
                                public String getFirstName() {
                                    return "";
                                }

                                @Override
                                public void setFirstName(String firstName) {

                                }

                                @Override
                                public String getLastName() {
                                    return "";
                                }

                                @Override
                                public void setLastName(String lastName) {

                                }

                                @Override
                                public String getEmail() {
                                    return "";
                                }

                                @Override
                                public void setEmail(String email) {

                                }

                                @Override
                                public boolean isEmailVerified() {
                                    return false;
                                }

                                @Override
                                public void setEmailVerified(boolean verified) {

                                }

                                @Override
                                public Stream<GroupModel> getGroupsStream() {
                                    return Stream.empty();
                                }

                                @Override
                                public void joinGroup(GroupModel group) {

                                }

                                @Override
                                public void leaveGroup(GroupModel group) {

                                }

                                @Override
                                public boolean isMemberOf(GroupModel group) {
                                    return false;
                                }

                                @Override
                                public String getFederationLink() {
                                    return "";
                                }

                                @Override
                                public void setFederationLink(String link) {

                                }

                                @Override
                                public String getServiceAccountClientLink() {
                                    return "";
                                }

                                @Override
                                public void setServiceAccountClientLink(String clientInternalId) {

                                }

                                @Override
                                public SubjectCredentialManager credentialManager() {
                                    return null;
                                }

                                @Override
                                public Stream<RoleModel> getRealmRoleMappingsStream() {
                                    return Stream.empty();
                                }

                                @Override
                                public Stream<RoleModel> getClientRoleMappingsStream(ClientModel app) {
                                    return Stream.empty();
                                }

                                @Override
                                public boolean hasRole(RoleModel role) {
                                    return true;
                                }

                                @Override
                                public void grantRole(RoleModel role) {

                                }

                                @Override
                                public Stream<RoleModel> getRoleMappingsStream() {
                                    return Stream.empty();
                                }

                                @Override
                                public void deleteRoleMapping(RoleModel role) {

                                }
                            };
                        }

                        @Override
                        public void setAuthenticatedUser(UserModel user) {

                        }

                        @Override
                        public Set<String> getRequiredActions() {
                            return Set.of();
                        }

                        @Override
                        public void addRequiredAction(String action) {

                        }

                        @Override
                        public void removeRequiredAction(String action) {

                        }

                        @Override
                        public void addRequiredAction(UserModel.RequiredAction action) {

                        }

                        @Override
                        public void removeRequiredAction(UserModel.RequiredAction action) {

                        }

                        @Override
                        public void setUserSessionNote(String name, String value) {

                        }

                        @Override
                        public Map<String, String> getUserSessionNotes() {
                            return Map.of();
                        }

                        @Override
                        public void clearUserSessionNotes() {

                        }

                        @Override
                        public String getAuthNote(String name) {
                            return "";
                        }

                        @Override
                        public void setAuthNote(String name, String value) {

                        }

                        @Override
                        public void removeAuthNote(String name) {

                        }

                        @Override
                        public void clearAuthNotes() {

                        }

                        @Override
                        public String getClientNote(String name) {
                            return "";
                        }

                        @Override
                        public void setClientNote(String name, String value) {

                        }

                        @Override
                        public void removeClientNote(String name) {

                        }

                        @Override
                        public Map<String, String> getClientNotes() {
                            return Map.of();
                        }

                        @Override
                        public void clearClientNotes() {

                        }

                        @Override
                        public Set<String> getClientScopes() {
                            return Set.of();
                        }

                        @Override
                        public void setClientScopes(Set<String> clientScopes) {

                        }
                    };
                }

                @Override
                public void setAuthenticationSession(AuthenticationSessionModel authenticationSession) {

                }

                @Override
                public HttpRequest getHttpRequest() {
                    return null;
                }

                @Override
                public HttpResponse getHttpResponse() {
                    return null;
                }

                @Override
                public void setConnection(ClientConnection clientConnection) {

                }

                @Override
                public void setHttpRequest(HttpRequest httpRequest) {

                }

                @Override
                public void setHttpResponse(HttpResponse httpResponse) {

                }

                @Override
                public UserSessionModel getUserSession() {
                    return null;
                }

                @Override
                public void setUserSession(UserSessionModel session) {

                }

                @Override
                public Token getBearerToken() {
                    return null;
                }

                @Override
                public void setBearerToken(Token token) {

                }

                @Override
                public URI getAuthServerUrl() {
                    return null;
                }

                @Override
                public String getContextPath() {
                    return "";
                }

                @Override
                public KeycloakUriInfo getUri() {
                    return null;
                }

                @Override
                public KeycloakUriInfo getUri(UrlType type) {
                    return null;
                }

                @Override
                public HttpHeaders getRequestHeaders() {
                    return null;
                }

                @Override
                public RealmModel getRealm() {
                    return new RealmModel() {
                        @Override
                        public String getId() {
                            return "";
                        }

                        @Override
                        public String getName() {
                            return "";
                        }

                        @Override
                        public void setName(String name) {

                        }

                        @Override
                        public String getDisplayName() {
                            return "";
                        }

                        @Override
                        public void setDisplayName(String displayName) {

                        }

                        @Override
                        public String getDisplayNameHtml() {
                            return "";
                        }

                        @Override
                        public void setDisplayNameHtml(String displayNameHtml) {

                        }

                        @Override
                        public boolean isEnabled() {
                            return false;
                        }

                        @Override
                        public void setEnabled(boolean enabled) {

                        }

                        @Override
                        public SslRequired getSslRequired() {
                            return null;
                        }

                        @Override
                        public void setSslRequired(SslRequired sslRequired) {

                        }

                        @Override
                        public boolean isRegistrationAllowed() {
                            return false;
                        }

                        @Override
                        public void setRegistrationAllowed(boolean registrationAllowed) {

                        }

                        @Override
                        public boolean isRegistrationEmailAsUsername() {
                            return false;
                        }

                        @Override
                        public void setRegistrationEmailAsUsername(boolean registrationEmailAsUsername) {

                        }

                        @Override
                        public boolean isRememberMe() {
                            return false;
                        }

                        @Override
                        public void setRememberMe(boolean rememberMe) {

                        }

                        @Override
                        public boolean isEditUsernameAllowed() {
                            return false;
                        }

                        @Override
                        public void setEditUsernameAllowed(boolean editUsernameAllowed) {

                        }

                        @Override
                        public boolean isUserManagedAccessAllowed() {
                            return false;
                        }

                        @Override
                        public void setUserManagedAccessAllowed(boolean userManagedAccessAllowed) {

                        }

                        @Override
                        public boolean isOrganizationsEnabled() {
                            return false;
                        }

                        @Override
                        public void setOrganizationsEnabled(boolean organizationsEnabled) {

                        }

                        @Override
                        public boolean isAdminPermissionsEnabled() {
                            return false;
                        }

                        @Override
                        public void setAdminPermissionsEnabled(boolean adminPermissionsEnabled) {

                        }

                        @Override
                        public boolean isVerifiableCredentialsEnabled() {
                            return false;
                        }

                        @Override
                        public void setVerifiableCredentialsEnabled(boolean verifiableCredentialsEnabled) {

                        }

                        @Override
                        public void setAttribute(String name, String value) {

                        }

                        @Override
                        public void removeAttribute(String name) {

                        }

                        @Override
                        public String getAttribute(String name) {
                            return "";
                        }

                        @Override
                        public Map<String, String> getAttributes() {
                            return Map.of();
                        }

                        @Override
                        public boolean isBruteForceProtected() {
                            return false;
                        }

                        @Override
                        public void setBruteForceProtected(boolean value) {

                        }

                        @Override
                        public boolean isPermanentLockout() {
                            return false;
                        }

                        @Override
                        public void setPermanentLockout(boolean val) {

                        }

                        @Override
                        public int getMaxTemporaryLockouts() {
                            return 0;
                        }

                        @Override
                        public void setMaxTemporaryLockouts(int val) {

                        }

                        @Override
                        public RealmRepresentation.BruteForceStrategy getBruteForceStrategy() {
                            return null;
                        }

                        @Override
                        public void setBruteForceStrategy(RealmRepresentation.BruteForceStrategy val) {

                        }

                        @Override
                        public int getMaxFailureWaitSeconds() {
                            return 0;
                        }

                        @Override
                        public void setMaxFailureWaitSeconds(int val) {

                        }

                        @Override
                        public int getWaitIncrementSeconds() {
                            return 0;
                        }

                        @Override
                        public void setWaitIncrementSeconds(int val) {

                        }

                        @Override
                        public int getMinimumQuickLoginWaitSeconds() {
                            return 0;
                        }

                        @Override
                        public void setMinimumQuickLoginWaitSeconds(int val) {

                        }

                        @Override
                        public long getQuickLoginCheckMilliSeconds() {
                            return 0;
                        }

                        @Override
                        public void setQuickLoginCheckMilliSeconds(long val) {

                        }

                        @Override
                        public int getMaxDeltaTimeSeconds() {
                            return 0;
                        }

                        @Override
                        public void setMaxDeltaTimeSeconds(int val) {

                        }

                        @Override
                        public int getFailureFactor() {
                            return 0;
                        }

                        @Override
                        public void setFailureFactor(int failureFactor) {

                        }

                        @Override
                        public boolean isVerifyEmail() {
                            return false;
                        }

                        @Override
                        public void setVerifyEmail(boolean verifyEmail) {

                        }

                        @Override
                        public boolean isLoginWithEmailAllowed() {
                            return false;
                        }

                        @Override
                        public void setLoginWithEmailAllowed(boolean loginWithEmailAllowed) {

                        }

                        @Override
                        public boolean isDuplicateEmailsAllowed() {
                            return false;
                        }

                        @Override
                        public void setDuplicateEmailsAllowed(boolean duplicateEmailsAllowed) {

                        }

                        @Override
                        public boolean isResetPasswordAllowed() {
                            return false;
                        }

                        @Override
                        public void setResetPasswordAllowed(boolean resetPasswordAllowed) {

                        }

                        @Override
                        public String getDefaultSignatureAlgorithm() {
                            return "";
                        }

                        @Override
                        public void setDefaultSignatureAlgorithm(String defaultSignatureAlgorithm) {

                        }

                        @Override
                        public boolean isRevokeRefreshToken() {
                            return false;
                        }

                        @Override
                        public void setRevokeRefreshToken(boolean revokeRefreshToken) {

                        }

                        @Override
                        public int getRefreshTokenMaxReuse() {
                            return 0;
                        }

                        @Override
                        public void setRefreshTokenMaxReuse(int revokeRefreshTokenCount) {

                        }

                        @Override
                        public int getSsoSessionIdleTimeout() {
                            return 0;
                        }

                        @Override
                        public void setSsoSessionIdleTimeout(int seconds) {

                        }

                        @Override
                        public int getSsoSessionMaxLifespan() {
                            return 0;
                        }

                        @Override
                        public void setSsoSessionMaxLifespan(int seconds) {

                        }

                        @Override
                        public int getSsoSessionIdleTimeoutRememberMe() {
                            return 0;
                        }

                        @Override
                        public void setSsoSessionIdleTimeoutRememberMe(int seconds) {

                        }

                        @Override
                        public int getSsoSessionMaxLifespanRememberMe() {
                            return 0;
                        }

                        @Override
                        public void setSsoSessionMaxLifespanRememberMe(int seconds) {

                        }

                        @Override
                        public int getOfflineSessionIdleTimeout() {
                            return 0;
                        }

                        @Override
                        public void setOfflineSessionIdleTimeout(int seconds) {

                        }

                        @Override
                        public int getAccessTokenLifespan() {
                            return 0;
                        }

                        @Override
                        public boolean isOfflineSessionMaxLifespanEnabled() {
                            return false;
                        }

                        @Override
                        public void setOfflineSessionMaxLifespanEnabled(boolean offlineSessionMaxLifespanEnabled) {

                        }

                        @Override
                        public int getOfflineSessionMaxLifespan() {
                            return 0;
                        }

                        @Override
                        public void setOfflineSessionMaxLifespan(int seconds) {

                        }

                        @Override
                        public int getClientSessionIdleTimeout() {
                            return 0;
                        }

                        @Override
                        public void setClientSessionIdleTimeout(int seconds) {

                        }

                        @Override
                        public int getClientSessionMaxLifespan() {
                            return 0;
                        }

                        @Override
                        public void setClientSessionMaxLifespan(int seconds) {

                        }

                        @Override
                        public int getClientOfflineSessionIdleTimeout() {
                            return 0;
                        }

                        @Override
                        public void setClientOfflineSessionIdleTimeout(int seconds) {

                        }

                        @Override
                        public int getClientOfflineSessionMaxLifespan() {
                            return 0;
                        }

                        @Override
                        public void setClientOfflineSessionMaxLifespan(int seconds) {

                        }

                        @Override
                        public void setAccessTokenLifespan(int seconds) {

                        }

                        @Override
                        public int getAccessTokenLifespanForImplicitFlow() {
                            return 0;
                        }

                        @Override
                        public void setAccessTokenLifespanForImplicitFlow(int seconds) {

                        }

                        @Override
                        public int getAccessCodeLifespan() {
                            return 0;
                        }

                        @Override
                        public void setAccessCodeLifespan(int seconds) {

                        }

                        @Override
                        public int getAccessCodeLifespanUserAction() {
                            return 0;
                        }

                        @Override
                        public void setAccessCodeLifespanUserAction(int seconds) {

                        }

                        @Override
                        public OAuth2DeviceConfig getOAuth2DeviceConfig() {
                            return null;
                        }

                        @Override
                        public CibaConfig getCibaPolicy() {
                            return null;
                        }

                        @Override
                        public ParConfig getParPolicy() {
                            return null;
                        }

                        @Override
                        public Map<String, Integer> getUserActionTokenLifespans() {
                            return Map.of();
                        }

                        @Override
                        public int getAccessCodeLifespanLogin() {
                            return 0;
                        }

                        @Override
                        public void setAccessCodeLifespanLogin(int seconds) {

                        }

                        @Override
                        public int getActionTokenGeneratedByAdminLifespan() {
                            return 0;
                        }

                        @Override
                        public void setActionTokenGeneratedByAdminLifespan(int seconds) {

                        }

                        @Override
                        public int getActionTokenGeneratedByUserLifespan() {
                            return 0;
                        }

                        @Override
                        public void setActionTokenGeneratedByUserLifespan(int seconds) {

                        }

                        @Override
                        public int getActionTokenGeneratedByUserLifespan(String actionTokenType) {
                            return 0;
                        }

                        @Override
                        public void setActionTokenGeneratedByUserLifespan(String actionTokenType, Integer seconds) {

                        }

                        @Override
                        public Stream<RequiredCredentialModel> getRequiredCredentialsStream() {
                            return Stream.empty();
                        }

                        @Override
                        public void addRequiredCredential(String cred) {

                        }

                        @Override
                        public PasswordPolicy getPasswordPolicy() {
                            return null;
                        }

                        @Override
                        public void setPasswordPolicy(PasswordPolicy policy) {

                        }

                        @Override
                        public OTPPolicy getOTPPolicy() {
                            return null;
                        }

                        @Override
                        public void setOTPPolicy(OTPPolicy policy) {

                        }

                        @Override
                        public WebAuthnPolicy getWebAuthnPolicy() {
                            return null;
                        }

                        @Override
                        public void setWebAuthnPolicy(WebAuthnPolicy policy) {

                        }

                        @Override
                        public WebAuthnPolicy getWebAuthnPolicyPasswordless() {
                            return null;
                        }

                        @Override
                        public void setWebAuthnPolicyPasswordless(WebAuthnPolicy policy) {

                        }

                        @Override
                        public RoleModel getRoleById(String id) {
                            return null;
                        }

                        @Override
                        public Stream<GroupModel> getDefaultGroupsStream() {
                            return Stream.empty();
                        }

                        @Override
                        public void addDefaultGroup(GroupModel group) {

                        }

                        @Override
                        public void removeDefaultGroup(GroupModel group) {

                        }

                        @Override
                        public Stream<ClientModel> getClientsStream() {
                            return Stream.empty();
                        }

                        @Override
                        public Stream<ClientModel> getClientsStream(Integer firstResult, Integer maxResults) {
                            return Stream.empty();
                        }

                        @Override
                        public Long getClientsCount() {
                            return 0L;
                        }

                        @Override
                        public Stream<ClientModel> getAlwaysDisplayInConsoleClientsStream() {
                            return Stream.empty();
                        }

                        @Override
                        public ClientModel addClient(String name) {
                            return null;
                        }

                        @Override
                        public ClientModel addClient(String id, String clientId) {
                            return null;
                        }

                        @Override
                        public boolean removeClient(String id) {
                            return false;
                        }

                        @Override
                        public ClientModel getClientById(String id) {
                            return null;
                        }

                        @Override
                        public ClientModel getClientByClientId(String clientId) {
                            return null;
                        }

                        @Override
                        public Stream<ClientModel> searchClientByClientIdStream(String clientId, Integer firstResult, Integer maxResults) {
                            return Stream.empty();
                        }

                        @Override
                        public Stream<ClientModel> searchClientByAttributes(Map<String, String> attributes, Integer firstResult, Integer maxResults) {
                            return Stream.empty();
                        }

                        @Override
                        public Stream<ClientModel> searchClientByAuthenticationFlowBindingOverrides(Map<String, String> overrides, Integer firstResult, Integer maxResults) {
                            return Stream.empty();
                        }

                        @Override
                        public void updateRequiredCredentials(Set<String> creds) {

                        }

                        @Override
                        public Map<String, String> getBrowserSecurityHeaders() {
                            return Map.of();
                        }

                        @Override
                        public void setBrowserSecurityHeaders(Map<String, String> headers) {

                        }

                        @Override
                        public Map<String, String> getSmtpConfig() {
                            return Map.of();
                        }

                        @Override
                        public void setSmtpConfig(Map<String, String> smtpConfig) {

                        }

                        @Override
                        public AuthenticationFlowModel getBrowserFlow() {
                            return null;
                        }

                        @Override
                        public void setBrowserFlow(AuthenticationFlowModel flow) {

                        }

                        @Override
                        public AuthenticationFlowModel getRegistrationFlow() {
                            return null;
                        }

                        @Override
                        public void setRegistrationFlow(AuthenticationFlowModel flow) {

                        }

                        @Override
                        public AuthenticationFlowModel getDirectGrantFlow() {
                            return null;
                        }

                        @Override
                        public void setDirectGrantFlow(AuthenticationFlowModel flow) {

                        }

                        @Override
                        public AuthenticationFlowModel getResetCredentialsFlow() {
                            return null;
                        }

                        @Override
                        public void setResetCredentialsFlow(AuthenticationFlowModel flow) {

                        }

                        @Override
                        public AuthenticationFlowModel getClientAuthenticationFlow() {
                            return null;
                        }

                        @Override
                        public void setClientAuthenticationFlow(AuthenticationFlowModel flow) {

                        }

                        @Override
                        public AuthenticationFlowModel getDockerAuthenticationFlow() {
                            return null;
                        }

                        @Override
                        public void setDockerAuthenticationFlow(AuthenticationFlowModel flow) {

                        }

                        @Override
                        public AuthenticationFlowModel getFirstBrokerLoginFlow() {
                            return null;
                        }

                        @Override
                        public void setFirstBrokerLoginFlow(AuthenticationFlowModel flow) {

                        }

                        @Override
                        public Stream<AuthenticationFlowModel> getAuthenticationFlowsStream() {
                            return Stream.empty();
                        }

                        @Override
                        public AuthenticationFlowModel getFlowByAlias(String alias) {
                            return null;
                        }

                        @Override
                        public AuthenticationFlowModel addAuthenticationFlow(AuthenticationFlowModel model) {
                            return null;
                        }

                        @Override
                        public AuthenticationFlowModel getAuthenticationFlowById(String id) {
                            return null;
                        }

                        @Override
                        public void removeAuthenticationFlow(AuthenticationFlowModel model) {

                        }

                        @Override
                        public void updateAuthenticationFlow(AuthenticationFlowModel model) {

                        }

                        @Override
                        public Stream<AuthenticationExecutionModel> getAuthenticationExecutionsStream(String flowId) {
                            return Stream.empty();
                        }

                        @Override
                        public AuthenticationExecutionModel getAuthenticationExecutionById(String id) {
                            return null;
                        }

                        @Override
                        public AuthenticationExecutionModel getAuthenticationExecutionByFlowId(String flowId) {
                            return null;
                        }

                        @Override
                        public AuthenticationExecutionModel addAuthenticatorExecution(AuthenticationExecutionModel model) {
                            return null;
                        }

                        @Override
                        public void updateAuthenticatorExecution(AuthenticationExecutionModel model) {

                        }

                        @Override
                        public void removeAuthenticatorExecution(AuthenticationExecutionModel model) {

                        }

                        @Override
                        public Stream<AuthenticatorConfigModel> getAuthenticatorConfigsStream() {
                            return Stream.empty();
                        }

                        @Override
                        public AuthenticatorConfigModel addAuthenticatorConfig(AuthenticatorConfigModel model) {
                            return null;
                        }

                        @Override
                        public void updateAuthenticatorConfig(AuthenticatorConfigModel model) {

                        }

                        @Override
                        public void removeAuthenticatorConfig(AuthenticatorConfigModel model) {

                        }

                        @Override
                        public AuthenticatorConfigModel getAuthenticatorConfigById(String id) {
                            return null;
                        }

                        @Override
                        public AuthenticatorConfigModel getAuthenticatorConfigByAlias(String alias) {
                            return null;
                        }

                        @Override
                        public RequiredActionConfigModel getRequiredActionConfigById(String id) {
                            return null;
                        }

                        @Override
                        public RequiredActionConfigModel getRequiredActionConfigByAlias(String alias) {
                            return null;
                        }

                        @Override
                        public void removeRequiredActionProviderConfig(RequiredActionConfigModel model) {

                        }

                        @Override
                        public void updateRequiredActionConfig(RequiredActionConfigModel model) {

                        }

                        @Override
                        public Stream<RequiredActionConfigModel> getRequiredActionConfigsStream() {
                            return Stream.empty();
                        }

                        @Override
                        public Stream<RequiredActionProviderModel> getRequiredActionProvidersStream() {
                            return Stream.empty();
                        }

                        @Override
                        public RequiredActionProviderModel addRequiredActionProvider(RequiredActionProviderModel model) {
                            return null;
                        }

                        @Override
                        public void updateRequiredActionProvider(RequiredActionProviderModel model) {

                        }

                        @Override
                        public void removeRequiredActionProvider(RequiredActionProviderModel model) {

                        }

                        @Override
                        public RequiredActionProviderModel getRequiredActionProviderById(String id) {
                            return null;
                        }

                        @Override
                        public RequiredActionProviderModel getRequiredActionProviderByAlias(String alias) {
                            return null;
                        }

                        @Override
                        public Stream<IdentityProviderModel> getIdentityProvidersStream() {
                            return Stream.empty();
                        }

                        @Override
                        public IdentityProviderModel getIdentityProviderByAlias(String alias) {
                            return null;
                        }

                        @Override
                        public void addIdentityProvider(IdentityProviderModel identityProvider) {

                        }

                        @Override
                        public void removeIdentityProviderByAlias(String alias) {

                        }

                        @Override
                        public void updateIdentityProvider(IdentityProviderModel identityProvider) {

                        }

                        @Override
                        public Stream<IdentityProviderMapperModel> getIdentityProviderMappersStream() {
                            return Stream.empty();
                        }

                        @Override
                        public Stream<IdentityProviderMapperModel> getIdentityProviderMappersByAliasStream(String brokerAlias) {
                            return Stream.empty();
                        }

                        @Override
                        public IdentityProviderMapperModel addIdentityProviderMapper(IdentityProviderMapperModel model) {
                            return null;
                        }

                        @Override
                        public void removeIdentityProviderMapper(IdentityProviderMapperModel mapping) {

                        }

                        @Override
                        public void updateIdentityProviderMapper(IdentityProviderMapperModel mapping) {

                        }

                        @Override
                        public IdentityProviderMapperModel getIdentityProviderMapperById(String id) {
                            return null;
                        }

                        @Override
                        public IdentityProviderMapperModel getIdentityProviderMapperByName(String brokerAlias, String name) {
                            return null;
                        }

                        @Override
                        public ComponentModel addComponentModel(ComponentModel model) {
                            return null;
                        }

                        @Override
                        public ComponentModel importComponentModel(ComponentModel model) {
                            return null;
                        }

                        @Override
                        public void updateComponent(ComponentModel component) {

                        }

                        @Override
                        public void removeComponent(ComponentModel component) {

                        }

                        @Override
                        public void removeComponents(String parentId) {

                        }

                        @Override
                        public Stream<ComponentModel> getComponentsStream(String parentId, String providerType) {
                            return Stream.empty();
                        }

                        @Override
                        public Stream<ComponentModel> getComponentsStream(String parentId) {
                            return Stream.empty();
                        }

                        @Override
                        public Stream<ComponentModel> getComponentsStream() {
                            return Stream.empty();
                        }

                        @Override
                        public ComponentModel getComponent(String id) {
                            return null;
                        }

                        @Override
                        public String getLoginTheme() {
                            return "";
                        }

                        @Override
                        public void setLoginTheme(String name) {

                        }

                        @Override
                        public String getAccountTheme() {
                            return "";
                        }

                        @Override
                        public void setAccountTheme(String name) {

                        }

                        @Override
                        public String getAdminTheme() {
                            return "";
                        }

                        @Override
                        public void setAdminTheme(String name) {

                        }

                        @Override
                        public String getEmailTheme() {
                            return "";
                        }

                        @Override
                        public void setEmailTheme(String name) {

                        }

                        @Override
                        public int getNotBefore() {
                            return 0;
                        }

                        @Override
                        public void setNotBefore(int notBefore) {

                        }

                        @Override
                        public boolean isEventsEnabled() {
                            return false;
                        }

                        @Override
                        public void setEventsEnabled(boolean enabled) {

                        }

                        @Override
                        public long getEventsExpiration() {
                            return 0;
                        }

                        @Override
                        public void setEventsExpiration(long expiration) {

                        }

                        @Override
                        public Stream<String> getEventsListenersStream() {
                            return Stream.empty();
                        }

                        @Override
                        public void setEventsListeners(Set<String> listeners) {

                        }

                        @Override
                        public Stream<String> getEnabledEventTypesStream() {
                            return Stream.empty();
                        }

                        @Override
                        public void setEnabledEventTypes(Set<String> enabledEventTypes) {

                        }

                        @Override
                        public boolean isAdminEventsEnabled() {
                            return false;
                        }

                        @Override
                        public void setAdminEventsEnabled(boolean enabled) {

                        }

                        @Override
                        public boolean isAdminEventsDetailsEnabled() {
                            return false;
                        }

                        @Override
                        public void setAdminEventsDetailsEnabled(boolean enabled) {

                        }

                        @Override
                        public ClientModel getMasterAdminClient() {
                            return null;
                        }

                        @Override
                        public void setMasterAdminClient(ClientModel client) {

                        }

                        @Override
                        public RoleModel getDefaultRole() {
                            return null;
                        }

                        @Override
                        public void setDefaultRole(RoleModel role) {

                        }

                        @Override
                        public ClientModel getAdminPermissionsClient() {
                            return null;
                        }

                        @Override
                        public void setAdminPermissionsClient(ClientModel client) {

                        }

                        @Override
                        public boolean isIdentityFederationEnabled() {
                            return false;
                        }

                        @Override
                        public boolean isInternationalizationEnabled() {
                            return false;
                        }

                        @Override
                        public void setInternationalizationEnabled(boolean enabled) {

                        }

                        @Override
                        public Stream<String> getSupportedLocalesStream() {
                            return Stream.empty();
                        }

                        @Override
                        public void setSupportedLocales(Set<String> locales) {

                        }

                        @Override
                        public String getDefaultLocale() {
                            return "";
                        }

                        @Override
                        public void setDefaultLocale(String locale) {

                        }

                        @Override
                        public GroupModel createGroup(String id, String name, GroupModel toParent) {
                            return null;
                        }

                        @Override
                        public GroupModel getGroupById(String id) {
                            return null;
                        }

                        @Override
                        public Stream<GroupModel> getGroupsStream() {
                            return Stream.empty();
                        }

                        @Override
                        public Long getGroupsCount(Boolean onlyTopGroups) {
                            return 0L;
                        }

                        @Override
                        public Long getGroupsCountByNameContaining(String search) {
                            return 0L;
                        }

                        @Override
                        public Stream<GroupModel> getTopLevelGroupsStream() {
                            return Stream.empty();
                        }

                        @Override
                        public Stream<GroupModel> getTopLevelGroupsStream(Integer first, Integer max) {
                            return Stream.empty();
                        }

                        @Override
                        public boolean removeGroup(GroupModel group) {
                            return false;
                        }

                        @Override
                        public void moveGroup(GroupModel group, GroupModel toParent) {

                        }

                        @Override
                        public Stream<ClientScopeModel> getClientScopesStream() {
                            return Stream.empty();
                        }

                        @Override
                        public ClientScopeModel addClientScope(String name) {
                            return null;
                        }

                        @Override
                        public ClientScopeModel addClientScope(String id, String name) {
                            return null;
                        }

                        @Override
                        public boolean removeClientScope(String id) {
                            return false;
                        }

                        @Override
                        public ClientScopeModel getClientScopeById(String id) {
                            return null;
                        }

                        @Override
                        public void addDefaultClientScope(ClientScopeModel clientScope, boolean defaultScope) {

                        }

                        @Override
                        public void removeDefaultClientScope(ClientScopeModel clientScope) {

                        }

                        @Override
                        public void createOrUpdateRealmLocalizationTexts(String locale, Map<String, String> localizationTexts) {

                        }

                        @Override
                        public boolean removeRealmLocalizationTexts(String locale) {
                            return false;
                        }

                        @Override
                        public Map<String, Map<String, String>> getRealmLocalizationTexts() {
                            return Map.of();
                        }

                        @Override
                        public Map<String, String> getRealmLocalizationTextsByLocale(String locale) {
                            return Map.of();
                        }

                        @Override
                        public Stream<ClientScopeModel> getDefaultClientScopesStream(boolean defaultScope) {
                            return Stream.empty();
                        }

                        @Override
                        public ClientInitialAccessModel createClientInitialAccessModel(int expiration, int count) {
                            return null;
                        }

                        @Override
                        public ClientInitialAccessModel getClientInitialAccessModel(String id) {
                            return null;
                        }

                        @Override
                        public void removeClientInitialAccessModel(String id) {

                        }

                        @Override
                        public Stream<ClientInitialAccessModel> getClientInitialAccesses() {
                            return Stream.empty();
                        }

                        @Override
                        public void decreaseRemainingCount(ClientInitialAccessModel clientInitialAccess) {

                        }

                        @Override
                        public RoleModel getRole(String name) {
                            return null;
                        }

                        @Override
                        public RoleModel addRole(String name) {
                            return null;
                        }

                        @Override
                        public RoleModel addRole(String id, String name) {
                            return null;
                        }

                        @Override
                        public boolean removeRole(RoleModel role) {
                            return false;
                        }

                        @Override
                        public Stream<RoleModel> getRolesStream() {
                            return Stream.empty();
                        }

                        @Override
                        public Stream<RoleModel> getRolesStream(Integer firstResult, Integer maxResults) {
                            return Stream.empty();
                        }

                        @Override
                        public Stream<RoleModel> searchForRolesStream(String search, Integer first, Integer max) {
                            return Stream.empty();
                        }
                    };
                }

                @Override
                public void setRealm(RealmModel realm) {

                }

                @Override
                public ClientModel getClient() {
                    return null;
                }

                @Override
                public void setClient(ClientModel client) {

                }

                @Override
                public OrganizationModel getOrganization() {
                    return null;
                }

                @Override
                public void setOrganization(OrganizationModel organization) {

                }

                @Override
                public ClientConnection getConnection() {
                    return null;
                }

                @Override
                public Locale resolveLocale(UserModel user) {
                    return null;
                }
            };

            @Override
            public KeycloakContext getContext() {
                return context;
            }

            @Override
            public KeycloakTransactionManager getTransactionManager() {
                return null;
            }

            @Override
            public <T extends Provider> T getProvider(Class<T> clazz) {
                return null;
            }

            @Override
            public <T extends Provider> T getProvider(Class<T> clazz, String id) {
                return null;
            }

            @Override
            public <T extends Provider> T getComponentProvider(Class<T> clazz, String componentId) {
                return null;
            }

            @Override
            public <T extends Provider> T getComponentProvider(Class<T> clazz, String componentId, Function<KeycloakSessionFactory, ComponentModel> modelGetter) {
                return null;
            }

            @Override
            public <T extends Provider> T getProvider(Class<T> clazz, ComponentModel componentModel) {
                return null;
            }

            @Override
            public <T extends Provider> Set<String> listProviderIds(Class<T> clazz) {
                return Set.of();
            }

            @Override
            public <T extends Provider> Set<T> getAllProviders(Class<T> clazz) {
                return Set.of();
            }

            @Override
            public Class<? extends Provider> getProviderClass(String providerClassName) {
                return null;
            }

            @Override
            public Object getAttribute(String attribute) {
                return null;
            }

            @Override
            public <T> T getAttribute(String attribute, Class<T> clazz) {
                return null;
            }

            @Override
            public Object removeAttribute(String attribute) {
                return null;
            }

            @Override
            public void setAttribute(String name, Object value) {

            }

            @Override
            public Map<String, Object> getAttributes() {
                return Map.of();
            }

            @Override
            public void invalidate(InvalidationHandler.InvalidableObjectType type, Object... params) {

            }

            @Override
            public void enlistForClose(Provider provider) {

            }

            @Override
            public KeycloakSessionFactory getKeycloakSessionFactory() {
                return null;
            }

            @Override
            public RealmProvider realms() {
                return null;
            }

            @Override
            public ClientProvider clients() {
                return null;
            }

            @Override
            public ClientScopeProvider clientScopes() {
                return null;
            }

            @Override
            public GroupProvider groups() {
                return null;
            }

            @Override
            public RoleProvider roles() {
                return null;
            }

            @Override
            public UserSessionProvider sessions() {
                return null;
            }

            @Override
            public UserLoginFailureProvider loginFailures() {
                return null;
            }

            @Override
            public AuthenticationSessionProvider authenticationSessions() {
                return null;
            }

            @Override
            public SingleUseObjectProvider singleUseObjects() {
                return null;
            }

            @Override
            public IdentityProviderStorageProvider identityProviders() {
                return null;
            }

            @Override
            public void close() {

            }

            @Override
            public UserProvider users() {
                return null;
            }

            @Override
            public KeyManager keys() {
                return null;
            }

            @Override
            public ThemeManager theme() {
                return null;
            }

            @Override
            public TokenManager tokens() {
                return null;
            }

            @Override
            public VaultTranscriber vault() {
                return null;
            }

            @Override
            public ClientPolicyManager clientPolicy() {
                return null;
            }

            @Override
            public boolean isClosed() {
                return false;
            }

        };
    }
}
