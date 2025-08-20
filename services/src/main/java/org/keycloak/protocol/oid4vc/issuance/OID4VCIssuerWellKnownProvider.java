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

import jakarta.ws.rs.core.UriInfo;
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
import org.keycloak.protocol.oid4vc.model.DisplayObject;

import org.keycloak.protocol.oid4vc.model.CredentialResponseEncryptionMetadata;
import org.keycloak.protocol.oid4vc.model.SupportedCredentialConfiguration;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;
import org.keycloak.urls.UrlType;
import org.keycloak.wellknown.WellKnownProvider;
import org.jboss.logging.Logger;
import org.keycloak.utils.MediaType;

import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.stream.Collectors;

import static org.keycloak.crypto.KeyType.RSA;

/**
 * {@link WellKnownProvider} implementation to provide the .well-known/openid-credential-issuer endpoint, offering
 * the Credential Issuer Metadata as defined by the OID4VCI protocol
 * {@see https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-11.2.2}
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public class OID4VCIssuerWellKnownProvider implements WellKnownProvider {

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
        CredentialIssuer issuer = new CredentialIssuer()
                .setCredentialIssuer(getIssuer(context))
                .setCredentialEndpoint(getCredentialsEndpoint(context))
                .setNonceEndpoint(getNonceEndpoint(context))
                .setDeferredCredentialEndpoint(getDeferredCredentialEndpoint(context))
                .setCredentialsSupported(getSupportedCredentials(keycloakSession))
                .setAuthorizationServers(List.of(getIssuer(context)))
                .setCredentialResponseEncryption(getCredentialResponseEncryption(keycloakSession))
                .setBatchCredentialIssuance(getBatchCredentialIssuance(keycloakSession))
                .setDisplay(getInternationalizedDisplay(keycloakSession));
        return issuer;
    }

    /**
     * Get internationalized display data based on Accept-Language header
     */
    private List<DisplayObject> getInternationalizedDisplay(KeycloakSession session) {
        RealmModel realm = session.getContext().getRealm();

        if (!realm.isInternationalizationEnabled()) {
            return null;
        }

        List<Locale> acceptableLanguages = session.getContext().getRequestHeaders().getAcceptableLanguages();

        // Only return display if Accept-Language header is present
        if (acceptableLanguages == null || acceptableLanguages.isEmpty()) {
            return null;
        }

        // Get the first supported language from the Accept-Language header
        Locale preferredLocale = null;
        for (Locale locale : acceptableLanguages) {
            if (realm.getSupportedLocalesStream().anyMatch(supported ->
                    supported.equals(locale.toLanguageTag()) ||
                            supported.startsWith(locale.getLanguage() + "-") ||
                            supported.equals(locale.getLanguage()))) {
                preferredLocale = locale;
                break;
            }
        }

        // If no supported language found in Accept-Language header, don't return display
        if (preferredLocale == null) {
            return null;
        }

        // Create display object with the preferred locale
        DisplayObject display = new DisplayObject();
        display.setLocale(preferredLocale.getLanguage());
        display.setName(realm.getDisplayName() != null ? realm.getDisplayName() : realm.getName());
        display.setLogo(realm.getAttribute("oid4vci.logo_url"));
        display.setDescription(realm.getAttribute("oid4vci.description"));
        display.setBackgroundColor(realm.getAttribute("oid4vci.background_color"));
        display.setTextColor(realm.getAttribute("oid4vci.text_color"));

        return List.of(display);
    }

    /**
     * Create signed JWT metadata if requested
     * Complies with OID4VCI specification section 11.2.3
     */
    public String createSignedMetadataJWT(Object metadata) {
        try {
            RealmModel realm = keycloakSession.getContext().getRealm();
            KeyManager keyManager = keycloakSession.keys();

            KeyWrapper activeKey = keyManager.getActiveKey(realm, KeyUse.SIG, "RS256");
            if (activeKey == null) {
                LOGGER.warn("No active signing key found for JWT metadata signing");
                return null;
            }

            String issuer = getIssuer(keycloakSession.getContext());
            long now = org.keycloak.common.util.Time.currentTime();

            // Create a JsonWebToken with the metadata as claims
            JsonWebToken jwt = new JsonWebToken();
            jwt.issuer(issuer);
            jwt.subject(issuer);
            jwt.iat(now);
            jwt.exp(now + 3600);
            jwt.setOtherClaims("metadata", metadata);

            SignatureProvider signatureProvider = keycloakSession.getProvider(SignatureProvider.class, "RS256");
            SignatureSignerContext signer = signatureProvider.signer(activeKey);

            return new JWSBuilder()
                    .type(Oid4VciConstants.SIGNED_METADATA_JWT_TYPE)
                    .kid(activeKey.getKid())
                    .jsonContent(jwt)
                    .sign(signer);

        } catch (Exception e) {
            LOGGER.warn("Failed to create signed metadata JWT", e);
            return null;
        }
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
