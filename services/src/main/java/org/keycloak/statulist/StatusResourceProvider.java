package org.keycloak.statulist;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.*;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Optional;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Path("/token-status")
public class StatusResourceProvider implements RealmResourceProvider {

    private static final Logger logger = LoggerFactory.getLogger(StatusResourceProvider.class);
    private final KeycloakSession session;

    // Define supported actions
    private static final Set<String> SUPPORTED_ACTIONS = new HashSet<>(Arrays.asList(
            "revoke", "suspend", "reactivate"
    ));

    public StatusResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    private void validateAdminAccess() {
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
            validateAdminAccess();
            if (request == null || request.getTokenId() == null || request.getTokenId().isEmpty()) {
                return createErrorResponse(Response.Status.BAD_REQUEST, "Token ID is required");
            }

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
            validateAdminAccess();
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
            validateAdminAccess();
            if (tokenId == null || tokenId.isEmpty()) {
                return createErrorResponse(Response.Status.BAD_REQUEST, "Token ID is required");
            }
            String status = getTokenStatusFromKeycloak(tokenId);
            TokenStatusRequest response = new TokenStatusRequest(tokenId, status, null);

            // If token is suspended, add suspension information to metadata
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

