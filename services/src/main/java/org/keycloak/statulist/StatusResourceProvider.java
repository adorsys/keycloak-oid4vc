package org.keycloak.statulist;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.*;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

@Path("/token-status")
public class StatusResourceProvider implements RealmResourceProvider {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private static final Logger logger = LoggerFactory.getLogger(StatusResourceProvider.class);
    private final KeycloakSession session;

    private boolean skipAdminAccessCheck = false;

    public void setSkipAdminAccessCheck(boolean skip) {
        this.skipAdminAccessCheck = skip;
    }

    // Define supported actions
    private static final Set<String> SUPPORTED_ACTIONS = new HashSet<>(Arrays.asList(
            "revoke", "suspend", "reactivate"
    ));

    public StatusResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    private void validateAdminAccess() {
        if (skipAdminAccessCheck) {
            return;
        }

        AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
        if (authSession == null) {
            throw new NotAuthorizedException("Authentication session not found");
        }
        UserModel user = authSession.getAuthenticatedUser();
        RealmModel realm = session.getContext().getRealm();

        if (user == null || !user.hasRole(realm.getRole("admin"))) {
            throw new NotAuthorizedException("User does not have admin privileges");
        }
    }

    @POST
    @Path("/publish")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response publishTokenStatus(TokenStatusRequest request) {
        try {
            // check if request is null
            if (request == null || request.getTokenId() == null || request.getTokenId().isEmpty()) {
                return createErrorResponse(Response.Status.BAD_REQUEST, "Token ID is required");
            }

            validateAdminAccess();

            String status = getTokenStatusFromKeycloak(request.getTokenId());
            if ("unknown".equals(status) || "revoked".equals(status)) {
                return createErrorResponse(Response.Status.BAD_REQUEST, "Cannot publish status for revoked or unknown token");
            }

            request.setStatus(status);
            logger.info("Token status published: tokenId={}, status={}", request.getTokenId(), request.getStatus());
            return Response.ok(request).build();
        } catch (NotAuthorizedException e) {
            return createErrorResponse(Response.Status.UNAUTHORIZED, e.getMessage());
        } catch (Exception e) {
            logger.error("Unexpected error in publishTokenStatus", e);
            return createErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "Unexpected error: " + e.getMessage());
        }
    }

    private String getTokenStatusFromKeycloak(String tokenId) {
        try {
            UserSessionProvider userSessionProvider = session.getProvider(UserSessionProvider.class);
            Optional<UserSessionModel> userSession = userSessionProvider.getUserSessionsStream(session.getContext().getRealm(), (UserModel) null)
                    .filter(s -> s.getId().equals(tokenId))
                    .findFirst();

            if (userSession.isEmpty()) {
                logger.warn("Token not found: {}", tokenId);
                return "unknown";
            }

            UserSessionModel sessionModel = userSession.get();

            // Check if session is marked as suspended
            if (sessionModel.getNotes().containsKey("suspended")) {
                return "suspended";
            }

            boolean isActive = sessionModel.getLastSessionRefresh() + sessionModel.getRealm().getSsoSessionMaxLifespan() > System.currentTimeMillis() / 1000;
            return isActive ? "active" : "revoked";
        } catch (Exception e) {
            logger.error("Error retrieving token status", e);
            return "error";
        }
    }

    @POST
    @Path("/update")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateTokenState(TokenStateUpdateRequest request) {
        try {
            // validate the request parameters
            if (request == null || request.getTokenId() == null || request.getTokenId().isEmpty()) {
                return createErrorResponse(Response.Status.BAD_REQUEST, "Token ID is required");
            }

            String action = request.getAction();
            if (action == null || action.isEmpty()) {
                return createErrorResponse(Response.Status.BAD_REQUEST, "Action is required");
            }

            if (!SUPPORTED_ACTIONS.contains(action)) {
                return createErrorResponse(Response.Status.BAD_REQUEST,
                        "Invalid action: Must be one of " + String.join(", ", SUPPORTED_ACTIONS));
            }


            validateAdminAccess();

            boolean success = updateTokenInKeycloak(request);
            return success ?
                    Response.ok(createSuccessResponse("Token state updated successfully with action: " + action)).build() :
                    createErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "Failed to update token state");

        } catch (NotAuthorizedException e) {
            return createErrorResponse(Response.Status.UNAUTHORIZED, e.getMessage());
        } catch (Exception e) {
            logger.error("Unexpected error in updateTokenState", e);
            return createErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "Unexpected error: " + e.getMessage());
        }
    }

    private boolean updateTokenInKeycloak(TokenStateUpdateRequest request) {
        try {
            UserSessionProvider userSessionProvider = session.getProvider(UserSessionProvider.class);
            Optional<UserSessionModel> userSession = userSessionProvider.getUserSessionsStream(session.getContext().getRealm(), (UserModel) null)
                    .filter(s -> s.getId().equals(request.getTokenId()))
                    .findFirst();

            if (userSession.isEmpty()) {
                logger.warn("Token not found for action {}: {}", request.getAction(), request.getTokenId());
                return false;
            }

            UserSessionModel sessionModel = userSession.get();
            String action = request.getAction();

            switch (action) {
                case "revoke":
                    userSessionProvider.removeUserSession(session.getContext().getRealm(), sessionModel);
                    logger.info("Token successfully revoked: {}", request.getTokenId());
                    break;

                case "suspend":
                    sessionModel.setNote("suspended", "true");
                    sessionModel.setNote("suspensionReason", request.getReason());
                    sessionModel.setNote("suspensionTime", String.valueOf(System.currentTimeMillis()));
                    logger.info("Token successfully suspended: {}", request.getTokenId());
                    break;

                case "reactivate":
                    sessionModel.removeNote("suspended");
                    sessionModel.removeNote("suspensionReason");
                    sessionModel.removeNote("suspensionTime");
                    logger.info("Token successfully reactivated: {}", request.getTokenId());
                    break;

                default:
                    logger.warn("Unsupported action attempted: {}", action);
                    return false;
            }

            return true;
        } catch (Exception e) {
            logger.error("Error updating token state", e);
            return false;
        }
    }
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getTokenStatus(@QueryParam("token") String tokenId) {
        try {
            // validate the token ID
            if (tokenId == null || tokenId.isEmpty()) {
                return createErrorResponse(Response.Status.BAD_REQUEST, "Token ID is required");
            }

            validateAdminAccess();

            String status = getTokenStatusFromKeycloak(tokenId);
            TokenStatusRequest response = new TokenStatusRequest(tokenId, status, null);

            if ("suspended".equals(status)) {
                UserSessionProvider userSessionProvider = session.getProvider(UserSessionProvider.class);
                Optional<UserSessionModel> userSession = userSessionProvider.getUserSessionsStream(session.getContext().getRealm(), (UserModel) null)
                        .filter(s -> s.getId().equals(tokenId))
                        .findFirst();

                if (userSession.isPresent()) {
                    UserSessionModel sessionModel = userSession.get();
                    TokenSuspensionMetadata metadata = new TokenSuspensionMetadata(
                            sessionModel.getNote("suspensionReason"),
                            sessionModel.getNote("suspensionTime")
                    );
                    response.setMetadata(metadata);
                }
            }

            return Response.ok(response).build();
        } catch (NotAuthorizedException e) {
            return createErrorResponse(Response.Status.UNAUTHORIZED, e.getMessage());
        } catch (Exception e) {
            logger.error("Unexpected error in getTokenStatus", e);
            return createErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "Unexpected error: " + e.getMessage());
        }
    }

    @GET
    @Path("/generate-reference-tokens")
    @Produces(MediaType.APPLICATION_JSON)
    public Response generateReferenceTokens(
            @QueryParam("statusListUri") String statusListUri
    ) {
        try {
            validateAdminAccess();

            // Validate that statusListUri is provided
            if (statusListUri == null || statusListUri.isEmpty()) {
                return createErrorResponse(Response.Status.BAD_REQUEST, "Status List URI is required");
            }

            UserSessionProvider userSessionProvider = session.getProvider(UserSessionProvider.class);
            RealmModel realm = session.getContext().getRealm();

            // Retrieve all active user sessions
            List<UserSessionModel> userSessions = userSessionProvider.getUserSessionsStream(realm, (UserModel) null)
                    .filter(this::isValidSessionForReferenceToken)
                    .toList();

            if (userSessions.isEmpty()) {
                return Response.ok("{\"message\": \"No active sessions found.\"}").build();
            }

            List<Map<String, String>> referenceTokenDetails = new ArrayList<>();
            int index = 0;
            for (UserSessionModel userSession : userSessions) {
                String referenceToken = generateReferenceToken(userSession, statusListUri, index);
                if (referenceToken != null) {
                    Map<String, String> tokenInfo = new HashMap<>();
                    tokenInfo.put("tokenId", userSession.getId());
                    tokenInfo.put("referenceToken", referenceToken);
                    tokenInfo.put("statusListIndex", String.valueOf(index));
                    referenceTokenDetails.add(tokenInfo);
                    index++;
                }
            }

            return Response.ok(referenceTokenDetails).build();
        } catch (NotAuthorizedException e) {
            return createErrorResponse(Response.Status.UNAUTHORIZED, e.getMessage());
        } catch (Exception e) {
            logger.error("Unexpected error in generateReferenceTokens", e);
            return createErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "Unexpected error: " + e.getMessage());
        }
    }

    private String generateReferenceToken(UserSessionModel userSession, String statusListUri, int statusListIndex) {
        try {
            // Validate input
            if (userSession == null || statusListUri == null || statusListUri.isEmpty()) {
                logger.warn("Invalid input for reference token generation");
                return null;
            }

            // Check if session is suspended
            if (userSession.getNotes().containsKey("suspended")) {
                logger.warn("Cannot generate reference token for suspended session");
                return null;
            }

            // Generate cryptographically secure random bytes for the token
            SecureRandom secureRandom = new SecureRandom();
            byte[] tokenBytes = new byte[32];
            secureRandom.nextBytes(tokenBytes);

            // Create a base64 encoded representation of the token bytes
            String tokenIdentifier = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);

            // Construct the reference token payload
            ObjectNode header = objectMapper.createObjectNode();
            header.put("alg", "ES256");
            header.put("kid", tokenIdentifier.substring(0, 10));

            ObjectNode payload = objectMapper.createObjectNode();
            ObjectNode statusList = objectMapper.createObjectNode();
            statusList.put("idx", statusListIndex);
            statusList.put("uri", statusListUri);

            // Add additional metadata about the session
            ObjectNode status = objectMapper.createObjectNode();
            status.set("status_list", statusList);
            payload.set("status", status);
            payload.put("jti", userSession.getId());
            payload.put("iat", System.currentTimeMillis() / 1000L);
            payload.put("exp", (userSession.getLastSessionRefresh() + userSession.getRealm().getSsoSessionMaxLifespan()) / 1000L);

            // Base64 encode header and payload
            String encodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    objectMapper.writeValueAsString(header).getBytes(StandardCharsets.UTF_8)
            );
            String encodedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    objectMapper.writeValueAsString(payload).getBytes(StandardCharsets.UTF_8)
            );

            String signature = generateSignature(encodedHeader, encodedPayload);

            // Combine all parts
            return String.format("%s.%s.%s", encodedHeader, encodedPayload, signature);
        } catch (Exception e) {
            assert userSession != null;
            logger.error("Error generating reference token for session: {}", userSession.getId(), e);
            return null;
        }
    }

    private String generateSignature(String header, String payload) {
        try {
            String signature = Base64.getUrlEncoder().withoutPadding().encodeToString("mock-signature".getBytes());
            logger.debug("Generated Signature: {}", signature);
            return signature;
        } catch (Exception e) {
            logger.error("Error generating signature", e);
            return null;
        }
    }

    private boolean isValidSessionForReferenceToken(UserSessionModel userSession) {
        if (userSession == null) return false;

        long currentTime = System.currentTimeMillis() / 1000;
        long sessionMaxLifespan = userSession.getRealm().getSsoSessionMaxLifespan();

        // Check if the session is suspended
        if (userSession.getNotes().containsKey("suspended")) {
            return false;
        }

        // Check if the session is still active
        return (userSession.getLastSessionRefresh() + sessionMaxLifespan > currentTime);
    }

    private Response createErrorResponse(Response.Status status, String message) {
        return Response.status(status).entity("{\"error\": \"" + message + "\"}").build();
    }

    private String createSuccessResponse(String message) {
        return "{\"message\": \"" + message + "\"}";
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {}
}

