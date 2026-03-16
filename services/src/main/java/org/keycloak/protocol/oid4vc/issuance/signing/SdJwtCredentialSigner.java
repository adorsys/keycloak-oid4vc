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

package org.keycloak.protocol.oid4vc.issuance.signing;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.CredentialBody;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.SdJwtCredentialBody;
import org.keycloak.protocol.oid4vc.model.CredentialBuildConfig;

import org.jboss.logging.Logger;

/**
 * {@link CredentialSigner} implementing the SD_JWT_VC format. It returns the signed SD-JWT as a String.
 * <p>
 * {@see https://drafts.oauth.net/oauth-sd-jwt-vc/draft-ietf-oauth-sd-jwt-vc.html}
 * {@see https://www.ietf.org/archive/id/draft-fett-oauth-selective-disclosure-jwt-02.html}
 */
public class SdJwtCredentialSigner extends AbstractCredentialSigner<String> {

    private static final Logger LOGGER = Logger.getLogger(SdJwtCredentialSigner.class);

    public SdJwtCredentialSigner(KeycloakSession keycloakSession) {
        super(keycloakSession);
    }

    @Override
    public String signCredential(CredentialBody credentialBody, CredentialBuildConfig credentialBuildConfig)
            throws CredentialSignerException {
        if (!(credentialBody instanceof SdJwtCredentialBody sdJwtCredentialBody)) {
            throw new CredentialSignerException("Credential body unexpectedly not of type SdJwtCredentialBody");
        }

        LOGGER.debugf("Sign credentials to sd-jwt format.");

        // Get the signer first to ensure we use the exact same key that will sign the credential
        SignatureSignerContext signer = getSigner(credentialBuildConfig);

        // Add x5c certificate chain to the header if available (required by HAIP-6.1.1)
        // See: https://openid.github.io/OpenID4VC-HAIP/openid4vc-high-assurance-interoperability-profile-wg-draft.html#section-6.1.1
        addX5cHeader(sdJwtCredentialBody, signer);

        return sdJwtCredentialBody.sign(signer);
    }

    /**
     * Adds x5c certificate chain to the IssuerSignedJWT header if available.
     * This is required by HAIP-6.1.1 for SD-JWT credentials.
     * <p>
     * Uses the certificate chain from the signer to ensure we use the exact same key
     * that will be used for signing, following Keycloak's established pattern.
     * <p>
     * The certificate chain originates from Keycloak's {@code KeyWrapper}, which reads
     * certificates from the realm key store. Self-signed certificates can appear in two
     * scenarios:
     * <ul>
     *   <li>A standalone self-signed certificate is the only certificate configured
     *       (common in dev/test environments). In this case {@code getCertificateChain()}
     *       returns a single-element list containing that self-signed certificate.</li>
     *   <li>An admin imported a full chain including the root CA (trust anchor) into
     *       the key store. The root CA is self-signed and must be stripped.</li>
     * </ul>
     * Both cases must be handled to comply with HAIP-6.1.1 requirements.
     * <p>
     * See <a href="https://openid.github.io/OpenID4VC-HAIP/openid4vc-high-assurance-interoperability-profile-wg-draft.html#section-6.1.1">HAIP Section 6.1.1</a>
     * for the requirement on issuer identification and key resolution.
     *
     * @param sdJwtCredentialBody The SD-JWT credential body to add x5c to
     * @param signer              The signer context containing the certificate(s) for the signing key
     */
    private void addX5cHeader(SdJwtCredentialBody sdJwtCredentialBody, SignatureSignerContext signer) {
        List<X509Certificate> normalizedChain = X509CertificateChainUtil.normalizeForX5c(signer.getCertificateChain());

        if (!normalizedChain.isEmpty()) {
            List<String> x5cList = normalizedChain.stream()
                    .map(cert -> {
                        try {
                            return Base64.getEncoder().encodeToString(cert.getEncoded());
                        } catch (CertificateEncodingException e) {
                            throw new RuntimeException(e);
                        }
                    })
                    .collect(Collectors.toList());

            sdJwtCredentialBody.getIssuerSignedJWT().getJwsHeader().setX5c(x5cList);
        } else {
            LOGGER.debugf("No certificate or certificate chain available for x5c header in SD-JWT credential.");
        }
    }
}
