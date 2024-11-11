package org.keycloak.protocol.oid4vc.issuance.abc;

public class BlueSimpleTestProvider implements SimpleTestProvider {

    @Override
    public String getGreeting() {
        return "Hello from BlueSimpleTestProvider";
    }
}
