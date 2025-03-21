package org.keycloak.statulist;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class StatusResourceProviderFactory implements RealmResourceProviderFactory {
    public static final String ID = "token-status";

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new StatusResourceProvider(session);
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void close() {

    }
}
