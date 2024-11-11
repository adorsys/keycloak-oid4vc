package org.keycloak.protocol.oid4vc.issuance.abc;

import org.keycloak.provider.Provider;

public interface SimpleTestProvider extends Provider {

    @Override
    default void close() {
    }

    String getGreeting();
}
