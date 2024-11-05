package org.keycloak.protocol.oid4vc.issuance.credentialbuilder;

import org.keycloak.Config;
import org.keycloak.component.ComponentFactory;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oid4vc.OID4VCEnvironmentProviderFactory;

/**
 * Provider Factory to create {@link  CredentialBuilder}'s
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public interface CredentialBuilderFactory extends ComponentFactory<CredentialBuilder, CredentialBuilder>, OID4VCEnvironmentProviderFactory {

    @Override
    default void init(Config.Scope config) {
    }

    @Override
    default void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    default void close() {
    }
}
