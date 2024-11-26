package org.keycloak.protocol.oid4vc.issuance.keybinding;

import org.keycloak.provider.Provider;
import org.keycloak.provider.Spi;

/**
 * Spi implementation of the creation of {@link ProofValidator}
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public class ProofValidatorSpi implements Spi {
    private static final String NAME = "proofValidator";

    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return ProofValidator.class;
    }

    @Override
    public Class<? extends ProofValidatorFactory> getProviderFactoryClass() {
        return ProofValidatorFactory.class;
    }
}

