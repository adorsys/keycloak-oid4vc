package org.keycloak.protocol.oid4vc.issuance.abc;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class BlueSimpleTestProviderFactory implements SimpleTestProviderFactory {

    @Override
    public SimpleTestProvider create(KeycloakSession session, ComponentModel model) {
        return new BlueSimpleTestProvider();
    }

    @Override
    public SimpleTestProvider create(KeycloakSession session) {
        return new BlueSimpleTestProvider();
    }

    @Override
    public String getId() {
        return SimpleTestProviderColor.BLUE;
    }

}
