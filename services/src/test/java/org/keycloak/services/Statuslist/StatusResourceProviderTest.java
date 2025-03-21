package org.keycloak.services.Statuslist;

import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.core.Response;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.statulist.StatusResourceProvider;
import org.keycloak.statulist.TokenStateUpdateRequest;
import org.keycloak.statulist.TokenStatusRequest;
import org.keycloak.statulist.TokenSuspensionMetadata;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.*;
import java.util.stream.Stream;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class StatusResourceProviderTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private KeycloakContext context;

    @Mock
    private AuthenticationSessionModel authSession;

    @Mock
    private UserModel userModel;

    @Mock
    private RealmModel realmModel;

    @Mock
    private RoleModel adminRole;

    @Mock
    private UserSessionProvider userSessionProvider;

    @Mock
    private UserSessionModel userSessionModel;

    private StatusResourceProvider provider;

    private final String validTokenId = "valid-token-id";
    private final String nonExistentTokenId = "non-existent-token-id";
    private final String revokedTokenId = "revoked-token-id";
    private final String suspendedTokenId = "suspended-token-id";
    private final Map<String, String> suspendedNotes = new HashMap<>();

    @Before
    public void setup() {
        // Set up the basic mocks
        when(session.getContext()).thenReturn(context);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getRealm()).thenReturn(realmModel);
        when(authSession.getAuthenticatedUser()).thenReturn(userModel);
        when(realmModel.getRole("admin")).thenReturn(adminRole);
        when(userModel.hasRole(adminRole)).thenReturn(true);

        // Set up UserSessionProvider
        when(session.getProvider(UserSessionProvider.class)).thenReturn(userSessionProvider);

        // Setup for valid token
        when(userSessionModel.getId()).thenReturn(validTokenId);
        when(userSessionModel.getRealm()).thenReturn(realmModel);
        when(userSessionModel.getLastSessionRefresh()).thenReturn((int) (System.currentTimeMillis() / 1000));
        when(realmModel.getSsoSessionMaxLifespan()).thenReturn(36000); // 10 hours in seconds
        when(userSessionModel.getNotes()).thenReturn(new HashMap<>());

        // Setup for suspended token
        suspendedNotes.put("suspended", "true");
        suspendedNotes.put("suspensionReason", "Security concern");
        suspendedNotes.put("suspensionTime", String.valueOf(System.currentTimeMillis()));

        // Create the provider
        provider = new StatusResourceProvider(session);
    }

    private void setupValidToken() {
        List<UserSessionModel> sessions = new ArrayList<>();
        sessions.add(userSessionModel);
        when(userSessionProvider.getUserSessionsStream(any(RealmModel.class), any(UserModel.class)))
                .thenReturn(sessions.stream());
    }

    private void setupSuspendedToken() {
        UserSessionModel suspendedSession = mock(UserSessionModel.class);
        when(suspendedSession.getId()).thenReturn(suspendedTokenId);
        when(suspendedSession.getRealm()).thenReturn(realmModel);
        when(suspendedSession.getNotes()).thenReturn(suspendedNotes);

        List<UserSessionModel> sessions = new ArrayList<>();
        sessions.add(suspendedSession);
        when(userSessionProvider.getUserSessionsStream(any(RealmModel.class), any(UserModel.class)))
                .thenReturn(sessions.stream());
    }

    private void setupNonExistentToken() {
        when(userSessionProvider.getUserSessionsStream(any(RealmModel.class), any(UserModel.class)))
                .thenReturn(Stream.empty());
    }

    @Test
    public void testGetResource() {
        Object resource = provider.getResource();
        assertNotNull(resource);
        assertEquals(provider, resource);
    }

    @Test
    public void testClose() {
        // Just ensuring it doesn't throw exception
        provider.close();
    }

    @Test
    public void testGetTokenStatus_ValidToken() {
        setupValidToken();

        Response response = provider.getTokenStatus(validTokenId);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        TokenStatusRequest entity = (TokenStatusRequest) response.getEntity();
        assertEquals(validTokenId, entity.getTokenId());
        assertEquals("active", entity.getStatus());
        assertNull(entity.getMetadata());
    }

    @Test
    public void testGetTokenStatus_SuspendedToken() {
        setupSuspendedToken();

        Response response = provider.getTokenStatus(suspendedTokenId);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        TokenStatusRequest entity = (TokenStatusRequest) response.getEntity();
        assertEquals(suspendedTokenId, entity.getTokenId());
        assertEquals("suspended", entity.getStatus());
        assertNotNull(entity.getMetadata());

        TokenSuspensionMetadata metadata = (TokenSuspensionMetadata) entity.getMetadata();
        assertEquals("Security concern", metadata.getReason());
        assertNotNull(metadata.getTimestamp());
    }

    @Test
    public void testGetTokenStatus_NonExistentToken() {
        setupNonExistentToken();

        Response response = provider.getTokenStatus(nonExistentTokenId);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        TokenStatusRequest entity = (TokenStatusRequest) response.getEntity();
        assertEquals(nonExistentTokenId, entity.getTokenId());
        assertEquals("unknown", entity.getStatus());
    }

    @Test
    public void testGetTokenStatus_EmptyTokenId() {
        Response response = provider.getTokenStatus("");

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        assertTrue(response.getEntity().toString().contains("Token ID is required"));
    }

    @Test
    public void testGetTokenStatus_NullTokenId() {
        Response response = provider.getTokenStatus(null);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        assertTrue(response.getEntity().toString().contains("Token ID is required"));
    }

    @Test
    public void testGetTokenStatus_NotAuthorized() {
        // Setup non-admin user
        when(userModel.hasRole(adminRole)).thenReturn(false);

        Response response = provider.getTokenStatus(validTokenId);

        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
        assertTrue(response.getEntity().toString().contains("User does not have admin privileges"));
    }

    @Test
    public void testPublishTokenStatus_ValidToken() {
        setupValidToken();

        TokenStatusRequest request = new TokenStatusRequest();
        request.setTokenId(validTokenId);

        Response response = provider.publishTokenStatus(request);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        TokenStatusRequest entity = (TokenStatusRequest) response.getEntity();
        assertEquals(validTokenId, entity.getTokenId());
        assertEquals("active", entity.getStatus());
    }

    @Test
    public void testPublishTokenStatus_NonExistentToken() {
        setupNonExistentToken();

        TokenStatusRequest request = new TokenStatusRequest();
        request.setTokenId(nonExistentTokenId);

        Response response = provider.publishTokenStatus(request);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        assertTrue(response.getEntity().toString().contains("Cannot publish status for revoked or unknown token"));
    }

    @Test
    public void testPublishTokenStatus_EmptyTokenId() {
        TokenStatusRequest request = new TokenStatusRequest();
        request.setTokenId("");

        Response response = provider.publishTokenStatus(request);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        assertTrue(response.getEntity().toString().contains("Token ID is required"));
    }

    @Test
    public void testPublishTokenStatus_NullRequest() {
        Response response = provider.publishTokenStatus(null);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        assertTrue(response.getEntity().toString().contains("Token ID is required"));
    }

    @Test
    public void testUpdateTokenState_RevokeAction() {
        setupValidToken();

        TokenStateUpdateRequest request = new TokenStateUpdateRequest();
        request.setTokenId(validTokenId);
        request.setAction("revoke");

        Response response = provider.updateTokenState(request);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        verify(userSessionProvider).removeUserSession(realmModel, userSessionModel);
    }

    @Test
    public void testUpdateTokenState_SuspendAction() {
        setupValidToken();

        TokenStateUpdateRequest request = new TokenStateUpdateRequest();
        request.setTokenId(validTokenId);
        request.setAction("suspend");
        request.setReason("Security concern");

        Response response = provider.updateTokenState(request);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        verify(userSessionModel).setNote("suspended", "true");
        verify(userSessionModel).setNote("suspensionReason", "Security concern");
        verify(userSessionModel).setNote(eq("suspensionTime"), anyString());
    }

    @Test
    public void testUpdateTokenState_ReactivateAction() {
        setupSuspendedToken();

        TokenStateUpdateRequest request = new TokenStateUpdateRequest();
        request.setTokenId(suspendedTokenId);
        request.setAction("reactivate");

        // Mock the suspended session
        UserSessionModel suspendedSession = mock(UserSessionModel.class);
        when(suspendedSession.getId()).thenReturn(suspendedTokenId);
        when(suspendedSession.getNotes()).thenReturn(suspendedNotes);

        List<UserSessionModel> sessions = new ArrayList<>();
        sessions.add(suspendedSession);
        when(userSessionProvider.getUserSessionsStream(any(RealmModel.class), any(UserModel.class)))
                .thenReturn(sessions.stream());

        Response response = provider.updateTokenState(request);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        verify(suspendedSession).removeNote("suspended");
        verify(suspendedSession).removeNote("suspensionReason");
        verify(suspendedSession).removeNote("suspensionTime");
    }

    @Test
    public void testUpdateTokenState_UnsupportedAction() {
        TokenStateUpdateRequest request = new TokenStateUpdateRequest();
        request.setTokenId(validTokenId);
        request.setAction("unsupported");

        Response response = provider.updateTokenState(request);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        assertTrue(response.getEntity().toString().contains("Invalid action"));
    }

    @Test
    public void testUpdateTokenState_EmptyAction() {
        TokenStateUpdateRequest request = new TokenStateUpdateRequest();
        request.setTokenId(validTokenId);
        request.setAction("");

        Response response = provider.updateTokenState(request);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        assertTrue(response.getEntity().toString().contains("Action is required"));
    }

    @Test
    public void testUpdateTokenState_NonExistentToken() {
        setupNonExistentToken();

        TokenStateUpdateRequest request = new TokenStateUpdateRequest();
        request.setTokenId(nonExistentTokenId);
        request.setAction("revoke");

        Response response = provider.updateTokenState(request);

        assertEquals(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), response.getStatus());
        assertTrue(response.getEntity().toString().contains("Failed to update token state"));
    }

    @Test
    public void testValidateAdminAccess_NoAuthSession() {
        when(context.getAuthenticationSession()).thenReturn(null);

        try {
            // Using reflection to test private method
            java.lang.reflect.Method method = StatusResourceProvider.class.getDeclaredMethod("validateAdminAccess");
            method.setAccessible(true);
            method.invoke(provider);
            fail("Expected NotAuthorizedException was not thrown");
        } catch (Exception e) {
            assertTrue(e.getCause() instanceof NotAuthorizedException);
            assertEquals("Authentication session not found", e.getCause().getMessage());
        }
    }

    @Test
    public void testValidateAdminAccess_NoUser() {
        when(authSession.getAuthenticatedUser()).thenReturn(null);

        try {
            // Using reflection to test private method
            java.lang.reflect.Method method = StatusResourceProvider.class.getDeclaredMethod("validateAdminAccess");
            method.setAccessible(true);
            method.invoke(provider);
            fail("Expected NotAuthorizedException was not thrown");
        } catch (Exception e) {
            assertTrue(e.getCause() instanceof NotAuthorizedException);
            assertEquals("User does not have admin privileges", e.getCause().getMessage());
        }
    }
}
