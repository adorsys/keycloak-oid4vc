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
package org.keycloak.protocol.oid4vc.issuance.credentialoffer;

import java.util.Map;
import java.util.Optional;

import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.protocol.oid4vc.OID4VCLoginProtocolFactory;
import org.keycloak.protocol.oid4vc.model.OID4VCAuthorizationDetail;
import org.keycloak.util.JsonSerialization;

import org.jboss.logging.Logger;

/**
 * Default implementation of {@link CredentialOfferStorage} that uses Keycloak's
 * {@link org.keycloak.models.SingleUseObjectProvider} for storage.
 * 
 * <p>This implementation is cluster-aware and cross-DC aware, as it relies on
 * Infinispan's distributed cache infrastructure through the singleUseObjects API.
 * The storage automatically handles expiration and prevents memory leaks through
 * the underlying cache's expiration mechanisms.
 */
class DefaultCredentialOfferStorage implements CredentialOfferStorage {

    private static final Logger LOGGER = Logger.getLogger(OID4VCLoginProtocolFactory.class);

    private static final String ENTRY_KEY = "json";
    private static final String CANONICAL_KEY = "offerId";

    private final KeycloakSession session;

    DefaultCredentialOfferStorage(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Calculates the lifespan in seconds from the current time to the expiration timestamp.
     * 
     * @param expiresAt Absolute expiration timestamp in seconds
     * @return Lifespan in seconds, or 0 if the entry is already expired
     */
    private long calculateLifespanSeconds(long expiresAt) {
        long currentTime = Time.currentTime();
        long lifespan = expiresAt - currentTime;
        
        // If already expired or about to expire immediately, skip storage
        // This prevents storing entries that won't be usable
        return Math.max(0, lifespan);

    }

    @Override
    public void putOfferState(CredentialOfferState entry) {

        // Skip storing if already expired (following pattern from InfinispanSingleUseObjectProviderFactory)
        long lifespanSeconds = calculateLifespanSeconds(entry.getExpiresAt());
        if (lifespanSeconds <= 0) {
            LOGGER.warnf("Credential offer state not stored - expired already");
            return;
        }
        
        SingleUseObjectProvider singleUseObjects = session.singleUseObjects();
        String offerId = entry.getCredentialsOfferId();
        String entryJson = JsonSerialization.valueAsString(entry);

        // Store canonical payload only once (offerId).
        singleUseObjects.put(offerId, lifespanSeconds, Map.of(ENTRY_KEY, entryJson));

        // Store nonce alias -> canonical key.
        singleUseObjects.put(entry.getNonce(), lifespanSeconds, Map.of(CANONICAL_KEY, offerId));

        // Store optional pre-authorized code alias -> canonical key.
        entry.getPreAuthorizedCode().ifPresent(it ->
                singleUseObjects.put(it, lifespanSeconds, Map.of(CANONICAL_KEY, offerId))
        );

        // Store optional credentialIdentifier aliases -> canonical key.
        Optional.ofNullable(entry.getAuthorizationDetails()).ifPresent(authDetails ->
                authDetails.stream()
                        .map(OID4VCAuthorizationDetail::getCredentialIdentifiers)
                        .filter(ids -> ids != null && !ids.isEmpty())
                        .flatMap(ids -> ids.stream().filter(id -> id != null && !id.isBlank()))
                        .forEach(credentialIdentifier ->
                                singleUseObjects.put(credentialIdentifier, lifespanSeconds, Map.of(CANONICAL_KEY, offerId)))
        );
    }

    @Override
    public CredentialOfferState getOfferStateById(String offerId) {
        return Optional.ofNullable(session.singleUseObjects().get(offerId))
                .map(o -> o.get(ENTRY_KEY))
                .map(o -> JsonSerialization.valueFromString(o, CredentialOfferState.class))
                .orElse(null);
    }

    @Override
    public CredentialOfferState getOfferStateByNonce(String nonce) {
        return getOfferStateByAlias(nonce);
    }

    @Override
    public CredentialOfferState getOfferStateByPreAuthorizedCode(String preAuthorizedCode) {
        return getOfferStateByAlias(preAuthorizedCode);
    }

    @Override
    public CredentialOfferState getOfferStateByCredentialIdentifier(String credentialIdentifier) {
        return getOfferStateByAlias(credentialIdentifier);
    }

    private CredentialOfferState getOfferStateByAlias(String alias) {
        return Optional.ofNullable(session.singleUseObjects().get(alias))
                .map(o -> o.get(CANONICAL_KEY))
                .map(this::getOfferStateById)
                .orElse(null);
    }

    @Override
    public void removeOfferState(CredentialOfferState offerState) {
        SingleUseObjectProvider singleUseObjects = session.singleUseObjects();
        singleUseObjects.remove(offerState.getCredentialsOfferId());
        singleUseObjects.remove(offerState.getNonce());
        offerState.getPreAuthorizedCode().ifPresent(singleUseObjects::remove);
        Optional.ofNullable(offerState.getAuthorizationDetails()).ifPresent(authDetails ->
                authDetails.stream()
                        .map(OID4VCAuthorizationDetail::getCredentialIdentifiers)
                        .filter(ids -> ids != null && !ids.isEmpty())
                        .flatMap(ids -> ids.stream().filter(id -> id != null && !id.isBlank()))
                        .forEach(singleUseObjects::remove)
        );
    }
}
