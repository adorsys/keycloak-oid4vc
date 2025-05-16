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

package org.keycloak.protocol.oid4vc.issuance.credentialbuilder;

import org.keycloak.protocol.oid4vc.model.CredentialBuildConfig;
                                                                                                       import org.keycloak.protocol.oid4vc.model.Proof;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.provider.Provider;

/**
 * Interface for building credentials in various formats.
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public interface CredentialBuilder extends Provider {

    @Override
    default void close() {
    }

    /**
     * Returns the format supported by this builder.
     */
    String getSupportedFormat();

    /**
     * Builds a credential body from a VerifiableCredential and configuration.
     */
    CredentialBody buildCredentialBody(VerifiableCredential verifiableCredential, CredentialBuildConfig credentialBuildConfig)
            throws CredentialBuilderException;

    /**
     * Builds a credential body with an optional proof for key binding, used for multiple credential issuance.
     */
    default CredentialBody buildCredentialBody(VerifiableCredential verifiableCredential, CredentialBuildConfig credentialBuildConfig, Proof proof)
            throws CredentialBuilderException {
        // Default implementation for backward compatibility: ignore proof and call the original method
        return buildCredentialBody(verifiableCredential, credentialBuildConfig);
    }
}
