package org.keycloak.services.Statuslist;

import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class MockUserSessionModel implements UserSessionModel {
    private final String id;
    private final long lastSessionRefresh;
    private final Map<String, String> notes;
    private final RealmModel realm;
    private long sessionMaxLifespan;

    public MockUserSessionModel(String id, long lastSessionRefresh, Map<String, String> notes, RealmModel realm) {
        this.id = id;
        this.lastSessionRefresh = lastSessionRefresh;
        this.notes = notes != null ? notes : new HashMap<>();
        this.realm = realm;

        // Default session max lifespan to 1 hour
        this.sessionMaxLifespan = 3600;
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public RealmModel getRealm() {
        return realm;
    }

    @Override
    public int getLastSessionRefresh() {
        return (int) lastSessionRefresh;
    }

    @Override
    public String getBrokerSessionId() {
        return "";
    }

    @Override
    public String getBrokerUserId() {
        return "";
    }

    @Override
    public void setLastSessionRefresh(int seconds) {
        // No-op for mock
    }

    @Override
    public boolean isOffline() {
        return false;
    }

    @Override
    public Map<String, AuthenticatedClientSessionModel> getAuthenticatedClientSessions() {
        return Map.of();
    }

    @Override
    public void removeAuthenticatedClientSessions(Collection<String> removedClientUUIDS) {
        // No-op for mock
    }

    @Override
    public String getNote(String name) {
        return notes.getOrDefault(name, "");
    }

    @Override
    public void setNote(String name, String value) {
        notes.put(name, value);
    }

    @Override
    public void removeNote(String name) {
        notes.remove(name);
    }

    @Override
    public Map<String, String> getNotes() {
        return notes;
    }

    @Override
    public State getState() {
        return null;
    }

    @Override
    public void setState(State state) {
        // No-op for mock
    }

    @Override
    public void restartSession(RealmModel realm, UserModel user, String loginUsername, String ipAddress, String authMethod, boolean rememberMe, String brokerSessionId, String brokerUserId) {
        // No-op for mock
    }

    @Override
    public UserModel getUser() {
        return null;
    }

    @Override
    public String getLoginUsername() {
        return null;
    }

    @Override
    public String getIpAddress() {
        return null;
    }

    @Override
    public String getAuthMethod() {
        return "";
    }

    @Override
    public boolean isRememberMe() {
        return false;
    }

    @Override
    public int getStarted() {
        return 0;
    }

    // Add a method to set custom session max lifespan for testing
    public void setSessionMaxLifespan(long seconds) {
        this.sessionMaxLifespan = seconds;
    }
}
