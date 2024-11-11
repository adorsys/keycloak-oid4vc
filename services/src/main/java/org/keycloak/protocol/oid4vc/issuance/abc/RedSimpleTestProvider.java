package org.keycloak.protocol.oid4vc.issuance.abc;

public class RedSimpleTestProvider implements SimpleTestProvider {

    @Override
    public String getGreeting() {
        return "Hello from RedSimpleTestProvider";
    }
}
