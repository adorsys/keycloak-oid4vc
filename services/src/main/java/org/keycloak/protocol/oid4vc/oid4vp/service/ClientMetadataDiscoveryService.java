/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.protocol.oid4vc.oid4vp.service;

import org.keycloak.crypto.SignatureProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import org.keycloak.protocol.oid4vc.oid4vp.model.prex.SdGenericFormat;
import org.keycloak.provider.ProviderFactory;

import java.util.List;

/**
 * Discovers client metadata as Keycloak acts as an OpenID4VP client.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#name-verifier-metadata-client-me">
 * Verifier Metadata (Client Metadata)</a>
 */
public class ClientMetadataDiscoveryService {

    private final KeycloakSession session;

    public ClientMetadataDiscoveryService(KeycloakSession session) {
        this.session = session;
    }

    public ClientMetadata getClientMetadata() {
        // Only SD-JWT presentations are supported for now.
        ClientMetadata.VpFormat vpFormat = new ClientMetadata.VpFormat();
        vpFormat.setVcSdJwt(getSdJwtVpFormat());

        // Aggregate metadata
        return new ClientMetadata()
                .setClientId(getClientId())
                .setVpFormat(vpFormat);
    }

    private String getClientId() {
        // The client ID is typically the hostname of the Keycloak server.
        return session.getContext().getUri().getBaseUri().getHost();
    }

    private SdGenericFormat getSdJwtVpFormat() {
        // This is about verification capabilities, so does not depend on current keys.
        var supportedSignatureAlgorithms = getSupportedSignatureAlgorithms();

        SdGenericFormat format = new SdGenericFormat();
        format.setSdJwtAlgValues(supportedSignatureAlgorithms);
        format.setKbJwtAlgValues(supportedSignatureAlgorithms);

        return format;
    }

    private List<String> getSupportedSignatureAlgorithms() {
        return session.getKeycloakSessionFactory()
                .getProviderFactoriesStream(SignatureProvider.class)
                .map(ProviderFactory::getId)
                .toList();
    }
}
