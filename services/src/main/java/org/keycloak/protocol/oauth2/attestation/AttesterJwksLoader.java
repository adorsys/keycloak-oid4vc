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

package org.keycloak.protocol.oauth2.attestation;

import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.PublicKeysWrapper;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.keys.PublicKeyLoader;
import org.keycloak.keys.PublicKeyStorageProvider;
import org.keycloak.keys.PublicKeyStorageUtils;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.util.JWKSUtils;
import org.keycloak.util.JsonSerialization;

import org.jboss.logging.Logger;

import java.io.IOException;

/**
 * Loader for attester public keys from client or realm configuration.
 */
public class AttesterJwksLoader implements PublicKeyLoader {

    private static final Logger logger = Logger.getLogger(AttesterJwksLoader.class);

    private final KeycloakSession session;
    private final ClientModel client;
    private final RealmModel realm;
    private final String issuer;

    public AttesterJwksLoader(KeycloakSession session, ClientModel client, RealmModel realm, String issuer) {
        this.session = session;
        this.client = client;
        this.realm = realm;
        this.issuer = issuer;
    }

    @Override
    public PublicKeysWrapper loadKeys() throws Exception {
        // First, try to load from client configuration
        String clientJwks = client.getAttribute("clientattest.jwks");
        if (clientJwks != null && !clientJwks.trim().isEmpty()) {
            try {
                JSONWebKeySet jwks = JsonSerialization.readValue(clientJwks, JSONWebKeySet.class);
                // Note: JWK.Use is deprecated but JWKSUtils.getKeyWrappersForUse() still requires it
                // The method internally converts to KeyUse enum
                return JWKSUtils.getKeyWrappersForUse(jwks, JWK.Use.SIG, true);
            } catch (IOException e) {
                logger.warnf(e, "Failed to parse client attestation JWKS for client '%s'", client.getClientId());
            }
        }

        // TODO: Add realm-level JWKS configuration if needed
        // For now, return empty wrapper if no JWKS found
        logger.debugf("No attester JWKS found for issuer '%s' and client '%s'", issuer, client.getClientId());
        return PublicKeysWrapper.EMPTY;
    }

    /**
     * Gets the attester public key wrapper for a given key ID and algorithm.
     * Uses the public key storage for caching.
     */
    public static KeyWrapper getAttesterPublicKeyWrapper(KeycloakSession session, ClientModel client, 
                                                         RealmModel realm, String issuer, String kid, String alg) {
        PublicKeyStorageProvider keyStorage = session.getProvider(PublicKeyStorageProvider.class);
        String modelKey = PublicKeyStorageUtils.getClientModelCacheKey(realm.getId(), client.getId()) + "::attester::" + issuer;
        AttesterJwksLoader loader = new AttesterJwksLoader(session, client, realm, issuer);
        return keyStorage.getPublicKey(modelKey, kid, alg, loader);
    }
}

