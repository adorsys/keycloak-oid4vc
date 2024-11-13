package org.keycloak.protocol.oid4vc.issuance.credentialbuilder;

import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;

/**
 * Builds verifiable credentials for the LDP_VC format.
 * {@see https://www.w3.org/TR/vc-data-model/}
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class LDCredentialBuilder extends AbstractCredentialBuilder {


    @Override
    public LocatorInfo getLocatorInfo() {
        return new LocatorInfo(Format.LDP_VC, null, null);
    }

    @Override
    public CredentialBody.LDCredentialBody buildCredentialBody(VerifiableCredential verifiableCredential)
            throws CredentialBuilderException {
        // The default credential format is basically this format,
        // so not much is to be done.
        return new CredentialBody.LDCredentialBody(verifiableCredential);
    }
}
