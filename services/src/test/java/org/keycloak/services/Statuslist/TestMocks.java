package org.keycloak.services.Statuslist;

import jakarta.ws.rs.core.HttpHeaders;
import org.keycloak.Token;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.enums.SslRequired;
import org.keycloak.component.ComponentModel;
import org.keycloak.http.HttpRequest;
import org.keycloak.http.HttpResponse;
import org.keycloak.models.*;
import org.keycloak.provider.InvalidationHandler;
import org.keycloak.provider.Provider;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.urls.UrlType;
import org.keycloak.vault.VaultTranscriber;

import java.net.URI;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

public class TestMocks {
    public static KeycloakSession createMockSession() {
        return createMockSession(null);
    }

    public static KeycloakSession createMockSession(UserSessionProvider userSessionProvider) {
        return new KeycloakSession() {
            private final KeycloakContext context = new KeycloakContext() {
                private RealmModel realm = new MockRealmModel();
                private ClientModel client = null;
                private AuthenticationSessionModel authenticationSession = new MockAuthenticationSessionModel();
                private UserSessionModel userSession = null;

                @Override
                public RealmModel getRealm() {
                    return realm;
                }

                @Override
                public void setRealm(RealmModel realm) {
                    this.realm = realm;
                }

                @Override
                public ClientModel getClient() {
                    return client;
                }

                @Override
                public void setClient(ClientModel client) {
                    this.client = client;
                }

                @Override
                public AuthenticationSessionModel getAuthenticationSession() {
                    return authenticationSession;
                }

                @Override
                public void setAuthenticationSession(AuthenticationSessionModel authenticationSession) {
                    this.authenticationSession = authenticationSession;
                }

                @Override
                public UserSessionModel getUserSession() {
                    return userSession;
                }

                @Override
                public void setUserSession(UserSessionModel session) {
                    this.userSession = session;
                }

                @Override
                public URI getAuthServerUrl() {
                    return null;
                }

                @Override
                public String getContextPath() {
                    return "/auth";
                }

                // Other minimal implementations remain the same
                @Override public OrganizationModel getOrganization() { return null; }
                @Override public void setOrganization(OrganizationModel organization) {}
                @Override public KeycloakUriInfo getUri() { return null; }
                @Override public KeycloakUriInfo getUri(UrlType type) { return null; }
                @Override public HttpHeaders getRequestHeaders() { return null; }
                @Override public ClientConnection getConnection() { return null; }
                @Override public HttpRequest getHttpRequest() { return null; }
                @Override public HttpResponse getHttpResponse() { return null; }
                @Override public void setConnection(ClientConnection clientConnection) {}
                @Override public void setHttpRequest(HttpRequest httpRequest) {}
                @Override public void setHttpResponse(HttpResponse httpResponse) {}
                @Override public Token getBearerToken() { return null; }
                @Override public void setBearerToken(Token token) {}
                @Override public Locale resolveLocale(UserModel user) { return null; }
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
            public UserSessionProvider sessions() {
                return userSessionProvider;
            }

            @Override
            public UserLoginFailureProvider loginFailures() {
                return null;
            }

            // Minimal provider implementations
            @Override public <T extends Provider> T getProvider(Class<T> clazz, String id) { return null; }

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

            @Override public <T extends Provider> Set<String> listProviderIds(Class<T> clazz) { return Set.of(); }

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

            // Minimal session methods
            @Override public void close() {}

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

            @Override public RealmProvider realms() { return null; }
            @Override public ClientProvider clients() { return null; }

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

            @Override public AuthenticationSessionProvider authenticationSessions() { return null; }

            @Override
            public SingleUseObjectProvider singleUseObjects() {
                return null;
            }

            @Override
            public IdentityProviderStorageProvider identityProviders() {
                return null;
            }
        };
    }

    // Mock implementations for internal classes
    private static class MockRealmModel implements RealmModel {
        @Override
        public String getId() {
            return "test-realm";
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

        @Override
        public String getName() {
            return "test-realm";
        }

        @Override
        public void setName(String name) {
            // No-op for mock
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
            return true;
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

    }

    private static class MockAuthenticationSessionModel implements AuthenticationSessionModel {
        private final Map<String, AuthenticationSessionModel.ExecutionStatus> executionStatuses = new HashMap<>();

        @Override
        public String getTabId() {
            return "test-tab-id";
        }

        @Override
        public void setExecutionStatus(String executionId, AuthenticationSessionModel.ExecutionStatus status) {
            executionStatuses.put(executionId, status);
        }

        @Override
        public void clearExecutionStatus() {

        }

        @Override
        public Map<String, AuthenticationSessionModel.ExecutionStatus> getExecutionStatus() {
            return executionStatuses;
        }

        // Minimal required implementations
        @Override public RootAuthenticationSessionModel getParentSession() { return null; }
        @Override public String getRedirectUri() { return ""; }

        @Override
        public void setRedirectUri(String uri) {

        }

        @Override public RealmModel getRealm() { return null; }
        @Override public ClientModel getClient() { return null; }
        @Override public String getAction() { return ""; }

        @Override
        public void setAction(String action) {

        }

        @Override public String getProtocol() { return ""; }

        @Override
        public void setProtocol(String method) {

        }

        @Override public UserModel getAuthenticatedUser() { return null; }

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
    }
    public class MockClientModel implements ClientModel {
        @Override
        public void updateClient() {

        }

        @Override
        public String getId() { return "mock-client-id"; }

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

        @Override
        public String getClientId() { return "mock-client"; }

        @Override
        public void setClientId(String clientId) {

        }

        @Override
        public String getName() {
            return "";
        }

        @Override
        public void setName(String name) {

        }

        @Override
        public String getDescription() {
            return "";
        }

        @Override
        public void setDescription(String description) {

        }

        @Override
        public boolean isEnabled() {
            return false;
        }

        @Override
        public void setEnabled(boolean enabled) {

        }

        @Override
        public boolean isAlwaysDisplayInConsole() {
            return false;
        }

        @Override
        public void setAlwaysDisplayInConsole(boolean alwaysDisplayInConsole) {

        }

        @Override
        public boolean isSurrogateAuthRequired() {
            return false;
        }

        @Override
        public void setSurrogateAuthRequired(boolean surrogateAuthRequired) {

        }

        @Override
        public Set<String> getWebOrigins() {
            return Set.of();
        }

        @Override
        public void setWebOrigins(Set<String> webOrigins) {

        }

        @Override
        public void addWebOrigin(String webOrigin) {

        }

        @Override
        public void removeWebOrigin(String webOrigin) {

        }

        @Override
        public Set<String> getRedirectUris() {
            return Set.of();
        }

        @Override
        public void setRedirectUris(Set<String> redirectUris) {

        }

        @Override
        public void addRedirectUri(String redirectUri) {

        }

        @Override
        public void removeRedirectUri(String redirectUri) {

        }

        @Override
        public String getManagementUrl() {
            return "";
        }

        @Override
        public void setManagementUrl(String url) {

        }

        @Override
        public String getRootUrl() {
            return "";
        }

        @Override
        public void setRootUrl(String url) {

        }

        @Override
        public String getBaseUrl() {
            return "";
        }

        @Override
        public void setBaseUrl(String url) {

        }

        @Override
        public boolean isBearerOnly() {
            return false;
        }

        @Override
        public void setBearerOnly(boolean only) {

        }

        @Override
        public int getNodeReRegistrationTimeout() {
            return 0;
        }

        @Override
        public void setNodeReRegistrationTimeout(int timeout) {

        }

        @Override
        public String getClientAuthenticatorType() {
            return "";
        }

        @Override
        public void setClientAuthenticatorType(String clientAuthenticatorType) {

        }

        @Override
        public boolean validateSecret(String secret) {
            return false;
        }

        @Override
        public String getSecret() {
            return "";
        }

        @Override
        public void setSecret(String secret) {

        }

        @Override
        public String getRegistrationToken() {
            return "";
        }

        @Override
        public void setRegistrationToken(String registrationToken) {

        }

        @Override
        public String getProtocol() {
            return "";
        }

        @Override
        public void setProtocol(String protocol) {

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
        public String getAuthenticationFlowBindingOverride(String binding) {
            return "";
        }

        @Override
        public Map<String, String> getAuthenticationFlowBindingOverrides() {
            return Map.of();
        }

        @Override
        public void removeAuthenticationFlowBindingOverride(String binding) {

        }

        @Override
        public void setAuthenticationFlowBindingOverride(String binding, String flowId) {

        }

        @Override
        public boolean isFrontchannelLogout() {
            return false;
        }

        @Override
        public void setFrontchannelLogout(boolean flag) {

        }

        @Override
        public boolean isFullScopeAllowed() {
            return false;
        }

        @Override
        public void setFullScopeAllowed(boolean value) {

        }

        @Override
        public boolean isPublicClient() {
            return false;
        }

        @Override
        public void setPublicClient(boolean flag) {

        }

        @Override
        public boolean isConsentRequired() {
            return false;
        }

        @Override
        public void setConsentRequired(boolean consentRequired) {

        }

        @Override
        public boolean isStandardFlowEnabled() {
            return false;
        }

        @Override
        public void setStandardFlowEnabled(boolean standardFlowEnabled) {

        }

        @Override
        public boolean isImplicitFlowEnabled() {
            return false;
        }

        @Override
        public void setImplicitFlowEnabled(boolean implicitFlowEnabled) {

        }

        @Override
        public boolean isDirectAccessGrantsEnabled() {
            return false;
        }

        @Override
        public void setDirectAccessGrantsEnabled(boolean directAccessGrantsEnabled) {

        }

        @Override
        public boolean isServiceAccountsEnabled() {
            return false;
        }

        @Override
        public void setServiceAccountsEnabled(boolean serviceAccountsEnabled) {

        }

        @Override
        public RealmModel getRealm() {
            return null;
        }

        @Override
        public void addClientScope(ClientScopeModel clientScope, boolean defaultScope) {

        }

        @Override
        public void addClientScopes(Set<ClientScopeModel> clientScopes, boolean defaultScope) {

        }

        @Override
        public void removeClientScope(ClientScopeModel clientScope) {

        }

        @Override
        public Map<String, ClientScopeModel> getClientScopes(boolean defaultScope) {
            return Map.of();
        }

        @Override
        public int getNotBefore() {
            return 0;
        }

        @Override
        public void setNotBefore(int notBefore) {

        }

        @Override
        public Map<String, Integer> getRegisteredNodes() {
            return Map.of();
        }

        @Override
        public void registerNode(String nodeHost, int registrationTime) {

        }

        @Override
        public void unregisterNode(String nodeHost) {

        }

        @Override
        public Stream<ProtocolMapperModel> getProtocolMappersStream() {
            return Stream.empty();
        }

        @Override
        public ProtocolMapperModel addProtocolMapper(ProtocolMapperModel model) {
            return null;
        }

        @Override
        public void removeProtocolMapper(ProtocolMapperModel mapping) {

        }

        @Override
        public void updateProtocolMapper(ProtocolMapperModel mapping) {

        }

        @Override
        public ProtocolMapperModel getProtocolMapperById(String id) {
            return null;
        }

        @Override
        public ProtocolMapperModel getProtocolMapperByName(String protocol, String name) {
            return null;
        }

        @Override
        public Stream<RoleModel> getScopeMappingsStream() {
            return Stream.empty();
        }

        @Override
        public Stream<RoleModel> getRealmScopeMappingsStream() {
            return Stream.empty();
        }

        @Override
        public void addScopeMapping(RoleModel role) {

        }

        @Override
        public void deleteScopeMapping(RoleModel role) {

        }

        @Override
        public boolean hasScope(RoleModel role) {
            return false;
        }

        // Implement other required methods
        // ...
    }
}
