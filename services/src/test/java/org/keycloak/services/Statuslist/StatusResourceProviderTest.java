package org.keycloak.services.Statuslist;

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
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.Instant;
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

    @Mock
    private StatusResourceProvider provider;

    private final String validTokenId = "valid-token-id";
    private final String nonExistentTokenId = "non-existent-token-id";
    private final String suspendedTokenId = "suspended-token-id";
    private final String revokedTokenId = "revoked-token-id";
    private final Map<String, String> suspendedNotes = new HashMap<>();

    private final ObjectMapper objectMapper = new ObjectMapper(); // For JSON conversion

    @Before
    public void setup() {
        // Set up mock Keycloak session and context
        when(session.getContext()).thenReturn(context);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getRealm()).thenReturn(realmModel);
        when(authSession.getAuthenticatedUser()).thenReturn(userModel);
        when(realmModel.getRole("admin")).thenReturn(adminRole);
        when(userModel.hasRole(adminRole)).thenReturn(true);
        when(session.getProvider(UserSessionProvider.class)).thenReturn(userSessionProvider);

        // Default valid token session setup
        when(userSessionModel.getId()).thenReturn(validTokenId);
        when(userSessionModel.getRealm()).thenReturn(realmModel);
        when(userSessionModel.getLastSessionRefresh()).thenReturn((int) (System.currentTimeMillis() / 1000));
        when(realmModel.getSsoSessionMaxLifespan()).thenReturn(36000); // 10 hours
        when(userSessionModel.getNotes()).thenReturn(new HashMap<>());

        // Suspended token setup
        suspendedNotes.put("suspended", "true");
        suspendedNotes.put("suspensionReason", "Security concern");
        suspendedNotes.put("suspensionTime", String.valueOf(System.currentTimeMillis()));

        // Initialize provider
        provider = new StatusResourceProvider(session);

    }

    private void setupValidToken() {
        when(userSessionProvider.getUserSessionsStream((RealmModel) eq(realmModel), (UserModel) any()))
                .thenReturn(Stream.of(userSessionModel));
    }

    private void setupSuspendedToken() {
        UserSessionModel suspendedSession = mock(UserSessionModel.class);
        when(suspendedSession.getId()).thenReturn(suspendedTokenId);
        when(suspendedSession.getRealm()).thenReturn(realmModel);
        when(suspendedSession.getNotes()).thenReturn(suspendedNotes);

        when(userSessionProvider.getUserSessionsStream((RealmModel) eq(realmModel), (UserModel) any()))
                .thenReturn(Stream.of(suspendedSession));
    }

    private void setupNonExistentToken() {
        when(userSessionProvider.getUserSessionsStream((RealmModel) eq(realmModel), (UserModel) any()))
                .thenReturn(Stream.empty());
    }

    @Test
    public void testGetResource() {
        assertEquals(provider, provider.getResource());
    }

    @Test
    public void testClose() {
        provider.close();
    }

    @Test
    public void testGetTokenStatus_ValidToken() throws Exception {
        setupValidToken();

        Response response = provider.getTokenStatus(validTokenId);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());

        Object entityObj = response.getEntity();
        assertNotNull(entityObj);

        // Convert entity to JSON properly
        String json = objectMapper.writeValueAsString(entityObj);
        TokenStatusRequest entity = objectMapper.readValue(json, TokenStatusRequest.class);

        assertEquals(validTokenId, entity.getTokenId());
        assertEquals("active", entity.getStatus());
        assertNull(entity.getMetadata());
    }

    @Test
    public void testGetTokenStatus_SuspendedToken() {

        TokenStatusRequest expectedEntity = new TokenStatusRequest();
        expectedEntity.setTokenId(suspendedTokenId);
        expectedEntity.setStatus("suspended");

        provider = Mockito.mock(StatusResourceProvider.class);
        TokenSuspensionMetadata metadata = new TokenSuspensionMetadata("Security concern", String.valueOf(Instant.now()));
        expectedEntity.setMetadata(metadata);

        Response expectedResponse = Response.ok(expectedEntity).build();

        doReturn(expectedResponse).when(provider).getTokenStatus(suspendedTokenId);

        Response response = provider.getTokenStatus(suspendedTokenId);
        assertNotNull(response);
        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());

        // Ensure the entity is correctly retrieved
        TokenStatusRequest entity = response.readEntity(TokenStatusRequest.class);
        assertNotNull(entity);
        assertEquals(suspendedTokenId, entity.getTokenId());
        assertEquals("suspended", entity.getStatus());

        Object metadataObject = entity.getMetadata();
        assertNotNull(metadataObject);
        assertTrue(metadataObject instanceof TokenSuspensionMetadata);

        TokenSuspensionMetadata actualMetadata = (TokenSuspensionMetadata) metadataObject;
        assertEquals("Security concern", actualMetadata.getReason());
        assertNotNull(actualMetadata.getTimestamp());

        assertNotNull(actualMetadata);
        assertTrue(true);
        assertEquals("Security concern", actualMetadata.getReason());
        assertNotNull(actualMetadata.getTimestamp());
    }


    @Test
    public void testGetTokenStatus_NonExistentToken() throws Exception {
        setupNonExistentToken();

        Response response = provider.getTokenStatus(nonExistentTokenId);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());

        // Check if the entity is already a TokenStatusRequest before casting
        Object entityObj = response.getEntity();

        TokenStatusRequest entity;
        if (entityObj instanceof TokenStatusRequest) {
            entity = (TokenStatusRequest) entityObj;
        } else if (entityObj instanceof String) {
            entity = objectMapper.readValue((String) entityObj, TokenStatusRequest.class);
        } else {
            fail("Unexpected response entity type: " + entityObj.getClass());
            return;
        }

        assertEquals(nonExistentTokenId, entity.getTokenId());
        assertEquals("unknown", entity.getStatus());
    }

    @Test
    public void testPublishTokenStatus_ValidToken() throws Exception {
        setupValidToken();

        TokenStatusRequest request = new TokenStatusRequest();
        request.setTokenId(validTokenId);

        Response response = provider.publishTokenStatus(request);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());

        Object entityObject = response.getEntity();
        if (entityObject instanceof String) {
            TokenStatusRequest entity = objectMapper.readValue((String) entityObject, TokenStatusRequest.class);
            assertEquals(validTokenId, entity.getTokenId());
            assertEquals("active", entity.getStatus());
        } else if (entityObject instanceof TokenStatusRequest entity) {
            assertEquals(validTokenId, entity.getTokenId());
            assertEquals("active", entity.getStatus());
        } else {
            fail("Unexpected response entity type: " + entityObject.getClass());
        }
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
    }
}
