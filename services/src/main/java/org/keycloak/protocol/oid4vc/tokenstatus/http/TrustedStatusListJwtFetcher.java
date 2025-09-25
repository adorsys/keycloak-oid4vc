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

package org.keycloak.protocol.oid4vc.tokenstatus.http;

import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.truststore.TruststoreProvider;

import java.security.KeyStore;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;

/**
 * Status list JWT data fetcher with trust enforcement.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class TrustedStatusListJwtFetcher extends SimpleStatusListJwtFetcher {

    public TrustedStatusListJwtFetcher(KeycloakSession session) {
        super(session);
    }

    @Override
    public String fetchStatusListJwt(String uri) throws ReferencedTokenValidationException {
        // Enforce HTTPS
        if (!uri.startsWith("https://")) {
            throw new ReferencedTokenValidationException("Status list JWT URI must use HTTPS: " + uri);
        }

        // Retrieve status list JWT
        String statusListJwt = _fetchStatusListJwt(uri);
        JWSInput jws = parseStatusListJwt(statusListJwt);

        // Enforce trust in X5C chain
        SignatureVerifierContext verifier = enforceX5CTrust(jws);

        // Verify signature
        validateJwsSignature(jws, verifier);

        return statusListJwt;
    }

    protected String _fetchStatusListJwt(String uri) throws ReferencedTokenValidationException {
        return super.fetchStatusListJwt(uri);
    }

    private JWSInput parseStatusListJwt(String statusListJwt) throws ReferencedTokenValidationException {
        try {
            return new JWSInput(statusListJwt);
        } catch (JWSInputException e) {
            throw new ReferencedTokenValidationException(
                    String.format("Retrieved status list is not a valid JWT: %s", statusListJwt), e
            );
        }
    }

    private SignatureVerifierContext enforceX5CTrust(JWSInput jws) throws ReferencedTokenValidationException {
        try {
            JWSHeader header = jws.getHeader();
            List<String> x5cList = header.getX5c();

            if (x5cList == null || x5cList.isEmpty()) {
                throw new ReferencedTokenValidationException("Missing x5c header in JWS");
            }

            // Convert base64-encoded certs into X509Certificate objects
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<X509Certificate> certs = new ArrayList<>();
            for (String certB64 : x5cList) {
                byte[] der = Base64.getDecoder().decode(certB64);
                certs.add((X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(der)));
            }

            // Validate chain against Keycloak truststore
            TruststoreProvider truststoreProvider = session.getProvider(TruststoreProvider.class);
            KeyStore truststore = truststoreProvider.getTruststore();
            CertPathValidator.getInstance("PKIX").validate(
                    cf.generateCertPath(certs),
                    new PKIXParameters(toTrustAnchors(truststore))
            );

            return toSignatureVerifier(certs.get(0), header.getAlgorithm().name());
        } catch (Exception e) {
            throw new ReferencedTokenValidationException("X5C validation failed", e);
        }
    }

    private static Set<TrustAnchor> toTrustAnchors(KeyStore truststore) throws Exception {
        Set<TrustAnchor> anchors = new HashSet<>();
        Enumeration<String> aliases = truststore.aliases();
        while (aliases.hasMoreElements()) {
            Certificate cert = truststore.getCertificate(aliases.nextElement());
            if (cert instanceof X509Certificate) {
                anchors.add(new TrustAnchor((X509Certificate) cert, null));
            }
        }
        return anchors;
    }

    private SignatureVerifierContext toSignatureVerifier(X509Certificate cert, String alg)
            throws ReferencedTokenValidationException {
        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setPublicKey(cert.getPublicKey());
        keyWrapper.setAlgorithm(alg);

        try {
            SignatureProvider signatureProvider = session.getProvider(
                    SignatureProvider.class,
                    keyWrapper.getAlgorithmOrDefault()
            );

            return signatureProvider.verifier(keyWrapper);
        } catch (Exception e) {
            throw new ReferencedTokenValidationException("Error deriving verifier from x5c certificate", e);
        }
    }

    private void validateJwsSignature(JWSInput jws, SignatureVerifierContext verifier)
            throws ReferencedTokenValidationException {
        try {
            if (!verifier.verify(jws.getEncodedSignatureInput().getBytes(), jws.getSignature())) {
                throw new ReferencedTokenValidationException("Invalid JWS signature");
            }
        } catch (Exception e) {
            throw new ReferencedTokenValidationException("Error during JWS signature verification", e);
        }
    }
}
