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

package org.keycloak.protocol.oid4vc.issuance;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.keycloak.common.util.Time;
import org.keycloak.constants.Oid4VciConstants;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.oid4vc.OID4VCLoginProtocolFactory;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.CredentialBuilder;
import org.keycloak.protocol.oid4vc.model.CredentialIssuer;

import org.keycloak.protocol.oid4vc.model.CredentialResponseEncryptionMetadata;
import org.keycloak.protocol.oid4vc.model.SupportedCredentialConfiguration;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;
import org.keycloak.urls.UrlType;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.MediaType;
import org.keycloak.wellknown.WellKnownProvider;
import org.jboss.logging.Logger;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.keycloak.constants.Oid4VciConstants.SIGNED_METADATA_JWT_TYPE;
import static org.keycloak.crypto.KeyType.RSA;

/**
 * {@link WellKnownProvider} implementation to provide the .well-known/openid-credential-issuer endpoint, offering
 * the Credential Issuer Metadata as defined by the OID4VCI protocol
 * {@see https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-11.2.2}
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public class OID4VCIssuerWellKnownProvider implements WellKnownProvider {

    // Realm attributes for signed metadata configuration
    public static final String SIGNED_METADATA_ENABLED_ATTR = "oid4vci.signed_metadata.enabled";
    public static final String SIGNED_METADATA_EXPIRATION_ATTR = "oid4vci.signed_metadata.exp";
    public static final String SIGNED_METADATA_ISS_ATTR = "oid4vci.signed_metadata.iss";
    public static final String SIGNED_METADATA_ALG_ATTR = "oid4vci.signed_metadata.alg";

    public static final String VC_KEY = "vc";

    private static final Logger LOGGER = Logger.getLogger(OID4VCIssuerWellKnownProvider.class);

    protected final KeycloakSession keycloakSession;

    public static final String ATTR_ENCRYPTION_REQUIRED = "oid4vci.encryption.required";

    public OID4VCIssuerWellKnownProvider(KeycloakSession keycloakSession) {
        this.keycloakSession = keycloakSession;
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public Object getConfig() {
        KeycloakContext context = keycloakSession.getContext();
        RealmModel realm = keycloakSession.getContext().getRealm();

        CredentialIssuer issuer = new CredentialIssuer()
                .setCredentialIssuer(getIssuer(context))
                .setCredentialEndpoint(getCredentialsEndpoint(context))
                .setNonceEndpoint(getNonceEndpoint(context))
                .setDeferredCredentialEndpoint(getDeferredCredentialEndpoint(context))
                .setCredentialsSupported(getSupportedCredentials(keycloakSession))
                .setAuthorizationServers(List.of(getIssuer(context)))
                .setCredentialResponseEncryption(getCredentialResponseEncryption(keycloakSession))
                .setBatchCredentialIssuance(getBatchCredentialIssuance(keycloakSession));

        // Check if a client requested signed metadata via Accept header
        String acceptHeader = context.getRequestHeaders().getHeaderString(HttpHeaders.ACCEPT);
        boolean jwtPreferred = acceptHeader != null && acceptHeader.contains(MediaType.APPLICATION_JWT);

        // Check if signed metadata is enabled
        boolean signedMetadataEnabled = Boolean.parseBoolean(realm.getAttribute(SIGNED_METADATA_ENABLED_ATTR));

        // Return signed metadata if enabled AND explicitly requested with application/jwt
        if (signedMetadataEnabled && jwtPreferred) {
            try {
                return generateSignedMetadata(issuer, keycloakSession);
            } catch (Exception e) {
                LOGGER.warnf(e, "Failed to generate signed metadata for issuer: %s", issuer.getCredentialIssuer());
                // Fall back to unsigned JSON if signed metadata generation fails
                return issuer;
            }
        }

        // Default to unsigned JSON (application/json)
        return issuer;
    }

    private static String getDeferredCredentialEndpoint(KeycloakContext context) {
        return getIssuer(context) + "/protocol/" + OID4VCLoginProtocolFactory.PROTOCOL_ID + "/deferred_credential";
    }

    private CredentialIssuer.BatchCredentialIssuance getBatchCredentialIssuance(KeycloakSession session) {
        RealmModel realm = session.getContext().getRealm();
        String batchSize = realm.getAttribute("batch_credential_issuance.batch_size");
        if (batchSize != null) {
            try {
                return new CredentialIssuer.BatchCredentialIssuance()
                        .setBatchSize(Integer.parseInt(batchSize));
            } catch (Exception e) {
                LOGGER.warnf(e, "Failed to parse batch_credential_issuance.batch_size from realm attributes.");
            }
        }
        return null;
    }

    /**
     * Generates signed metadata as a JWS using JsonWebToken infrastructure.
     *
     * @param metadata The CredentialIssuer metadata object to sign.
     * @param session  The Keycloak session.
     * @return The compact JWS string.
     * @throws IllegalStateException if generation fails due to configuration or signing issues.
     */
    public String generateSignedMetadata(CredentialIssuer metadata, KeycloakSession session) {
        RealmModel realm = session.getContext().getRealm();
        KeyManager keyManager = session.keys();

        // Select asymmetric signing algorithm
        String alg = getSigningAlgorithm(realm, session);

        // Retrieve active key
        KeyWrapper keyWrapper = keyManager.getActiveKey(realm, KeyUse.SIG, alg);
        if (keyWrapper == null) {
            throw new IllegalStateException(
                    String.format("No active key found for realm '%s' with algorithm '%s'", realm.getName(), alg));
        }

        // Create JsonWebToken with metadata as claims
        JsonWebToken jwt = createMetadataJwt(metadata, realm);

        // Build JWS with proper headers
        JWSBuilder jwsBuilder = new JWSBuilder()
                .type(SIGNED_METADATA_JWT_TYPE)
                .kid(keyWrapper.getKid());

        // Add x5c certificate chain if available
        addCertificateHeaders(jwsBuilder, keyWrapper, realm);

        // Sign the JWS
        SignatureProvider signerProvider = session.getProvider(SignatureProvider.class, alg);
        if (signerProvider == null) {
            throw new IllegalStateException("No signature provider for algorithm: " + alg);
        }

        SignatureSignerContext signer = signerProvider.signer(keyWrapper);
        if (signer == null) {
            throw new IllegalStateException("No signer context for algorithm: " + alg);
        }

        try {
            return jwsBuilder.jsonContent(jwt).sign(signer);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign metadata", e);
        }
    }

    private String getSigningAlgorithm(RealmModel realm, KeycloakSession session) {
        List<String> supportedAlgorithms = getSupportedSignatureAlgorithms(session)
                .stream()
                .filter(alg -> !alg.startsWith("HS")) // Filter out symmetric algorithms
                .collect(Collectors.toList());

        if (supportedAlgorithms.isEmpty()) {
            throw new IllegalStateException("No asymmetric signing algorithms available for realm: " + realm.getName());
        }

        return Optional.ofNullable(realm.getAttribute(SIGNED_METADATA_ALG_ATTR))
                .filter(supportedAlgorithms::contains)
                .orElse(supportedAlgorithms.get(0));
    }

    private JsonWebToken createMetadataJwt(CredentialIssuer metadata, RealmModel realm) {
        JsonWebToken jwt = new JsonWebToken();

        // Set standard JWT claims
        jwt.subject(metadata.getCredentialIssuer());
        jwt.iat((long) Time.currentTime());
        jwt.issuedNow();

        // Set optional issuer claim
        Optional.ofNullable(realm.getAttribute(SIGNED_METADATA_ISS_ATTR))
                .ifPresent(jwt::issuer);

        // Set optional expiration
        Optional.ofNullable(realm.getAttribute(SIGNED_METADATA_EXPIRATION_ATTR))
                .map(expDurationStr -> {
                    try {
                        return Long.parseLong(expDurationStr);
                    } catch (NumberFormatException e) {
                        LOGGER.warnf("Invalid expiration duration for signed metadata: %s", expDurationStr);
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .ifPresent(expDuration -> jwt.exp(Time.currentTime() + expDuration));

        // Convert metadata to map and add as other claims
        Map<String, Object> metadataClaims = JsonSerialization.mapper.convertValue(metadata, Map.class);
        metadataClaims.forEach(jwt::setOtherClaims);

        return jwt;
    }

    private void addCertificateHeaders(JWSBuilder jwsBuilder, KeyWrapper keyWrapper, RealmModel realm) {
        if (keyWrapper.getCertificateChain() != null && !keyWrapper.getCertificateChain().isEmpty()) {
            jwsBuilder.x5c(keyWrapper.getCertificateChain());
        } else if (keyWrapper.getCertificate() != null) {
            jwsBuilder.x5c(List.of(keyWrapper.getCertificate()));
        } else {
            LOGGER.warnf("No certificate or certificate chain available for x5c header in realm: %s", realm.getName());
        }
    }


    /**
     * Returns the credential response encryption высоко for the issuer.
     * Now determines supported algorithms from available realm keys.
     *
     * @param session The Keycloak session
     * @return The credential response encryption metadata
     */
    public static CredentialResponseEncryptionMetadata getCredentialResponseEncryption(KeycloakSession session) {
        RealmModel realm = session.getContext().getRealm();
        CredentialResponseEncryptionMetadata metadata = new CredentialResponseEncryptionMetadata();

        // Get supported algorithms from available encryption keys
        metadata.setAlgValuesSupported(getSupportedEncryptionAlgorithms(session));
        metadata.setEncValuesSupported(getSupportedEncryptionMethods());
        metadata.setEncryptionRequired(isEncryptionRequired(realm));

        return metadata;
    }

    /**
     * Returns the supported encryption algorithms from realm attributes.
     */
    public static List<String> getSupportedEncryptionAlgorithms(KeycloakSession session) {
        RealmModel realm = session.getContext().getRealm();
        KeyManager keyManager = session.keys();

        List<String> supportedEncryptionAlgorithms = keyManager.getKeysStream(realm)
                .filter(key -> KeyUse.ENC.equals(key.getUse()))
                .map(KeyWrapper::getAlgorithm)
                .filter(algorithm -> algorithm != null && !algorithm.isEmpty())
                .distinct()
                .collect(Collectors.toList());

        if (supportedEncryptionAlgorithms.isEmpty()) {
            boolean hasRsaKeys = keyManager.getKeysStream(realm)
                    .filter(key -> KeyUse.ENC.equals(key.getUse()))
                    .anyMatch(key -> RSA.equals(key.getType()));

            if (hasRsaKeys) {
                supportedEncryptionAlgorithms.add(JWEConstants.RSA_OAEP);
                supportedEncryptionAlgorithms.add(JWEConstants.RSA_OAEP_256);
            }
        }

        return supportedEncryptionAlgorithms;
    }

    /**
     * Returns the supported encryption methods from realm attributes.
     */
    private static List<String> getSupportedEncryptionMethods() {
        return List.of(JWEConstants.A256GCM);
    }

    /**
     * Returns whether encryption is required from realm attributes.
     */
    private static boolean isEncryptionRequired(RealmModel realm) {
        String required = realm.getAttribute(ATTR_ENCRYPTION_REQUIRED);
        return Boolean.parseBoolean(required);
    }

    /**
     * Return the supported credentials from the current session.
     * It will take into account the configured {@link CredentialBuilder}'s and their supported format
     * and the credentials supported by the clients available in the session.
     */
    public static Map<String, SupportedCredentialConfiguration> getSupportedCredentials(KeycloakSession keycloakSession) {
        List<String> globalSupportedSigningAlgorithms = getSupportedSignatureAlgorithms(keycloakSession);

        RealmModel realm = keycloakSession.getContext().getRealm();
        Map<String, SupportedCredentialConfiguration> supportedCredentialConfigurations =
                keycloakSession.clientScopes()
                        .getClientScopesByProtocol(realm, Oid4VciConstants.OID4VC_PROTOCOL)
                        .map(CredentialScopeModel::new)
                        .map(clientScope -> {
                            return SupportedCredentialConfiguration.parse(keycloakSession,
                                    clientScope,
                                    globalSupportedSigningAlgorithms
                            );
                        })
                        .collect(Collectors.toMap(SupportedCredentialConfiguration::getId, sc -> sc, (sc1, sc2) -> sc1));

        return supportedCredentialConfigurations;
    }

    public static SupportedCredentialConfiguration toSupportedCredentialConfiguration(KeycloakSession keycloakSession,
                                                                                      CredentialScopeModel credentialModel) {
        List<String> globalSupportedSigningAlgorithms = getSupportedSignatureAlgorithms(keycloakSession);
        return SupportedCredentialConfiguration.parse(keycloakSession,
                credentialModel,
                globalSupportedSigningAlgorithms);
    }

    /**
     * Return the url of the issuer.
     */
    public static String getIssuer(KeycloakContext context) {
        UriInfo frontendUriInfo = context.getUri(UrlType.FRONTEND);
        return Urls.realmIssuer(frontendUriInfo.getBaseUri(),
                context.getRealm().getName());
    }

    /**
     * Return the nonce endpoint address
     */
    public static String getNonceEndpoint(KeycloakContext context) {
        return getIssuer(context) + "/protocol/" + OID4VCLoginProtocolFactory.PROTOCOL_ID + "/" +
                OID4VCIssuerEndpoint.NONCE_PATH;
    }

    /**
     * Return the credentials endpoint address
     */
    public static String getCredentialsEndpoint(KeycloakContext context) {
        return getIssuer(context) + "/protocol/" + OID4VCLoginProtocolFactory.PROTOCOL_ID + "/" + OID4VCIssuerEndpoint.CREDENTIAL_PATH;
    }

    public static List<String> getSupportedSignatureAlgorithms(KeycloakSession session) {
        RealmModel realm = session.getContext().getRealm();
        KeyManager keyManager = session.keys();

        return keyManager.getKeysStream(realm)
                .filter(key -> KeyUse.SIG.equals(key.getUse()))
                .map(KeyWrapper::getAlgorithm)
                .filter(algorithm -> algorithm != null && !algorithm.isEmpty())
                .distinct()
                .collect(Collectors.toList());
    }

}
