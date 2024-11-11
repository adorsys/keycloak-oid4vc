package org.keycloak.protocol.oid4vc.issuance.abc;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;

public class RedSimpleTestProviderFactory implements SimpleTestProviderFactory {

    @Override
    public SimpleTestProvider create(KeycloakSession session, ComponentModel model) {
        return new RedSimpleTestProvider();
    }

    @Override
    public SimpleTestProvider create(KeycloakSession session) {
        return new RedSimpleTestProvider();
    }

    @Override
    public String getId() {
        return SimpleTestProviderColor.RED;
    }
}
