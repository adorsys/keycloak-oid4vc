/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.protocol.oid4vc.issuance.signers;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.VCIssuerException;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.CredentialBody;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.JwtCredentialBody;
import org.keycloak.protocol.oid4vc.model.CredentialBuildConfig;

/**
 * {@link CredentialSigner} implementing the JWT_VC format. It returns the signed JWT-Credential as a String.
 * <p></p>
 * {@see https://identity.foundation/jwt-vc-presentation-profile/}
 */
public class JwtCredentialSigner extends AbstractCredentialSigner {

    private static final Logger LOGGER = Logger.getLogger(JwtCredentialSigner.class);

    protected JwtCredentialSigner(KeycloakSession keycloakSession) {
        super(keycloakSession);
    }

    @Override
    public String signCredential(CredentialBody credentialBody, CredentialBuildConfig credentialBuildConfig)
            throws VCIssuerException {
        LOGGER.debugf("Sign credentials to jwt-vc format.");

        if (!(credentialBody instanceof JwtCredentialBody jwtCredentialBody)) {
            throw new VCIssuerException("Credential body unexpectedly not of type JwtCredentialBody");
        }

        return jwtCredentialBody.sign(getSigner(credentialBuildConfig));
    }
}