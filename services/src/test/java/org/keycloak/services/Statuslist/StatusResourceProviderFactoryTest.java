package org.keycloak.services.Statuslist;

import org.junit.Test;
import org.junit.jupiter.api.Assertions;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientProvider;
import org.keycloak.models.ClientScopeProvider;
import org.keycloak.models.GroupProvider;
import org.keycloak.models.IdentityProviderStorageProvider;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.RoleProvider;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.ThemeManager;
import org.keycloak.models.TokenManager;
import org.keycloak.models.UserLoginFailureProvider;
import org.keycloak.models.UserProvider;
import org.keycloak.models.UserSessionProvider;
import org.keycloak.provider.InvalidationHandler;
import org.keycloak.provider.Provider;
import org.keycloak.services.clientpolicy.ClientPolicyManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.statulist.StatusResourceProvider;
import org.keycloak.statulist.StatusResourceProviderFactory;
import org.keycloak.vault.VaultTranscriber;

import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;


public class StatusResourceProviderFactoryTest {

    @Test
    public void testFactoryCreation() {
        StatusResourceProviderFactory factory = new StatusResourceProviderFactory();

        // Test ID
        Assertions.assertEquals("token-status", factory.getId());

        // Test resource provider creation
        KeycloakSession mockSession = createMockSession();
        RealmResourceProvider provider = factory.create(mockSession);

        Assertions.assertNotNull(provider);
        assertInstanceOf(StatusResourceProvider.class, provider);
    }

   // mock session helper
    private KeycloakSession createMockSession() {
        return new KeycloakSession() {
            @Override
            public KeycloakContext getContext() {
                return null;
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
