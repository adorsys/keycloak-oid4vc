package org.keycloak.protocol.oid4vc.issuance.abc;

import org.keycloak.Config;
import org.keycloak.component.ComponentFactory;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public interface SimpleTestProviderFactory extends ComponentFactory<SimpleTestProvider, SimpleTestProvider> {

    @Override
    default void init(Config.Scope config) {
    }

    @Override
    default void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    default void close() {
    }


    @Override
    default String getHelpText() {
        return null;
    }

    @Override
    default List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }
}
