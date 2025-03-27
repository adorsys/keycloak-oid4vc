package org.keycloak.services.Statuslist;

import jakarta.ws.rs.core.Response;
import org.junit.Test;
import org.junit.Assert;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.statulist.StatusResourceProvider;
import org.keycloak.statulist.TokenStateUpdateRequest;
import org.keycloak.statulist.TokenStatusRequest;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.lang.reflect.Method;

import static org.keycloak.services.Statuslist.TestMocks.createMockSession;

public class StatusResourceProviderTest {
    private static KeycloakSession mockSession = createMockSession();
    private static StatusResourceProvider resourceProvider = new StatusResourceProvider(mockSession);

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
        TokenStatusRequest request = new TokenStatusRequest();
        request.setTokenId("");

        Response response = resourceProvider.publishTokenStatus(request);

        Assert.assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        Assert.assertTrue(response.getEntity().toString().contains("Token ID is required"));
    }

    @Test
    public void testUpdateTokenState_InvalidAction() {
        // Setup
        KeycloakSession mockSession = TestMocks.createMockSession();
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

    @Test
    public void testGenerateReferenceToken_ValidSession() {

        MockUserSessionModel userSession = getMockUserSessionModel();

        // Use reflection to access the private method
        try {
            Method method = StatusResourceProvider.class.getDeclaredMethod(
                    "generateReferenceToken",
                    UserSessionModel.class,
                    String.class,
                    int.class
            );
            method.setAccessible(true);

            // Generate reference token
            String referenceToken = (String) method.invoke(
                    resourceProvider,
                    userSession,
                    "https://example.com/status-list",
                    1
            );

            // Assertions
            Assert.assertNotNull(referenceToken);

            // Verify token structure (JWT-like format with 3 parts separated by dots)
            String[] tokenParts = referenceToken.split("\\.");
            Assert.assertEquals(3, tokenParts.length);

            // Verify parts are base64 encoded
            Base64.getUrlDecoder().decode(tokenParts[0]);
            Base64.getUrlDecoder().decode(tokenParts[1]);
            Base64.getUrlDecoder().decode(tokenParts[2]);
        } catch (Exception e) {
            Assert.fail("Exception during test: " + e.getMessage());
        }
    }

    private MockUserSessionModel getMockUserSessionModel() {
        Map<String, String> emptyNotes = new HashMap<>();
        MockUserSessionModel userSession = new MockUserSessionModel(
                "test-session-id",
                // Set last refresh to current time to ensure the session is not expired
                System.currentTimeMillis() / 1000,
                emptyNotes,
                mockSession.getContext().getRealm()
        ) {
            // Override getLastSessionRefresh to return a recent timestamp
            @Override
            public int getLastSessionRefresh() {
                return (int) (System.currentTimeMillis() / 1000);
            }

            // Override getRealm to return a realm with a long session max lifespan
            @Override
            public RealmModel getRealm() {
                RealmModel realm = super.getRealm();
                // Ensure the session max lifespan is long enough to prevent expiration
                try {
                    wait(realm.getSsoSessionMaxLifespan());
                    long l = 3600L;// 1 hour
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                return realm;
            }
        };
        return userSession;
    }

    @Test
    public void testGenerateReferenceToken_SuspendedSession() {
        // Prepare a suspended user session
        Map<String, String> notes = new HashMap<>();
        notes.put("suspended", "true");
        MockUserSessionModel userSession = new MockUserSessionModel(
                "suspended-session-id",
                System.currentTimeMillis() / 1000 - 1000,
                notes,
                mockSession.getContext().getRealm()
        );

        // Use reflection to access the private method
        try {
            Method method = StatusResourceProvider.class.getDeclaredMethod(
                    "generateReferenceToken",
                    UserSessionModel.class,
                    String.class,
                    int.class
            );
            method.setAccessible(true);

            // Attempt to generate reference token
            String referenceToken = (String) method.invoke(
                    resourceProvider,
                    userSession,
                    "https://example.com/status-list",
                    1
            );

            // Assertions
            Assert.assertNull(referenceToken);
        } catch (Exception e) {
            Assert.fail("Exception during test: " + e.getMessage());
        }
    }

    @Test
    public void testGenerateReferenceToken_ExpiredSession() {
        // Prepare an expired user session
        Map<String, String> emptyNotes = new HashMap<>();
        MockUserSessionModel userSession = new MockUserSessionModel(
                "expired-session-id",
                System.currentTimeMillis() / 1000 - 100000,
                emptyNotes,
                mockSession.getContext().getRealm()
        );

        // Use reflection to access the private method
        try {
            Method method = StatusResourceProvider.class.getDeclaredMethod(
                    "generateReferenceToken",
                    UserSessionModel.class,
                    String.class,
                    int.class
            );
            method.setAccessible(true);

            // Attempt to generate reference token
            String referenceToken = (String) method.invoke(
                    resourceProvider,
                    userSession,
                    "https://example.com/status-list",
                    1
            );

            // Assertions
            Assert.assertNull(referenceToken);
        } catch (Exception e) {
            Assert.fail("Exception during test: " + e.getMessage());
        }
    }

    @Test
    public void testGenerateReferenceToken_InvalidInputs() {
        try {
            Method method = StatusResourceProvider.class.getDeclaredMethod(
                    "generateReferenceToken",
                    UserSessionModel.class,
                    String.class,
                    int.class
            );
            method.setAccessible(true);

            // Test with null session
            String referenceToken = (String) method.invoke(
                    resourceProvider,
                    null,
                    "https://example.com/status-list",
                    1
            );
            Assert.assertNull(referenceToken);

            // Test with empty URI
            MockUserSessionModel userSession = new MockUserSessionModel(
                    "test-session-id",
                    System.currentTimeMillis() / 1000 - 1000,
                    new HashMap<>(),
                    mockSession.getContext().getRealm()
            );
            referenceToken = (String) method.invoke(
                    resourceProvider,
                    userSession,
                    "",
                    1
            );
            Assert.assertNull(referenceToken);
        } catch (Exception e) {
            Assert.fail("Exception during test: " + e.getMessage());
        }
    }
}
