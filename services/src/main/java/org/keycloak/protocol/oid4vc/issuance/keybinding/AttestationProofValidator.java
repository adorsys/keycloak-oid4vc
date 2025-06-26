package org.keycloak.protocol.oid4vc.issuance.keybinding;

import com.fasterxml.jackson.core.type.TypeReference;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProvider;
import org.keycloak.protocol.oid4vc.issuance.VCIssuanceContext;
import org.keycloak.protocol.oid4vc.issuance.VCIssuerException;
import org.keycloak.protocol.oid4vc.model.AttestationProof;
import org.keycloak.protocol.oid4vc.model.ISO18045ResistanceLevel;
import org.keycloak.protocol.oid4vc.model.Proof;
import org.keycloak.protocol.oid4vc.model.ProofTypeMetadata;
import org.keycloak.protocol.oid4vc.model.ProofTypesSupported;
import org.keycloak.protocol.oid4vc.model.SupportedCredentialConfiguration;
import org.keycloak.util.JsonSerialization;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Validates attestation proofs as per OID4VCI specification.
 */
public class AttestationProofValidator extends AbstractProofValidator {

    private static final String ATTESTATION_JWT_TYP = "keyattestation+jwt";
    private static final String CACERTS_PATH = System.getProperty("java.home") + "/lib/security/cacerts";
    private static final char[] DEFAULT_TRUSTSTORE_PASSWORD = "changeit".toCharArray();

    public AttestationProofValidator(KeycloakSession session) {
        super(session);
    }

    @Override
    public List<JWK> validateProof(VCIssuanceContext vcIssuanceContext) throws VCIssuerException {
        try {
            return validateAttestationProof(vcIssuanceContext);
        } catch (IOException | JWSInputException | VerificationException | GeneralSecurityException e) {
            throw new VCIssuerException("Failed to validate attestation proof", e);
        }
    }

    private List<JWK> validateAttestationProof(VCIssuanceContext vcIssuanceContext)
            throws IOException, GeneralSecurityException, JWSInputException, VerificationException {

        AttestationProof proof = extractAttestationProof(vcIssuanceContext);
        String jwt = Optional.ofNullable(proof.getAttestation())
                .orElseThrow(() -> new VCIssuerException("Attestation JWT is missing"));

        JWSInput jwsInput = new JWSInput(jwt);
        JWSHeader header = jwsInput.getHeader();
        validateJwsHeader(vcIssuanceContext, header);

        SignatureVerifierContext verifier = verifierFromX5CChain(
                Optional.ofNullable(header.getX5c())
                        .filter(list -> !list.isEmpty())
                        .orElseThrow(() -> new VCIssuerException("Missing x5c header in attestation JWT")),
                header.getAlgorithm().name()
        );

        boolean isVerified = verifier.verify(
                jwsInput.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8),
                jwsInput.getSignature()
        );
        if (!isVerified) {
            throw new VCIssuerException("Invalid signature on attestation JWT");
        }

        Map<String, Object> payload = JsonSerialization.mapper.readValue(
                jwsInput.getContent(),
                new TypeReference<>() {}
        );

        validateAttestationPayload(vcIssuanceContext, payload);

        List<Map<String, Object>> keyMaps = (List<Map<String, Object>>) payload.get("attested_keys");
        if (keyMaps == null || keyMaps.isEmpty()) {
            throw new VCIssuerException("No attested_keys found in attestation payload");
        }

        List<JWK> jwks = new ArrayList<>();
        for (Map<String, Object> keyMap : keyMaps) {
            jwks.add(JsonSerialization.mapper.convertValue(keyMap, JWK.class));
        }

        return jwks;
    }

    private AttestationProof extractAttestationProof(VCIssuanceContext vcIssuanceContext)
            throws VCIssuerException {

        SupportedCredentialConfiguration config = Optional.ofNullable(vcIssuanceContext.getCredentialConfig())
                .orElseThrow(() -> new VCIssuerException("Credential configuration is missing"));

        if (config.getProofTypesSupported() == null ||
                config.getProofTypesSupported().getAttestation() == null) {
            throw new VCIssuerException("Attestation proof type not supported");
        }

        Proof proof = vcIssuanceContext.getCredentialRequest().getProof();
        if (!(proof instanceof AttestationProof attestationProof)) {
            throw new VCIssuerException("Expected attestation proof type, found: " +
                    (proof == null ? "null" : proof.getClass().getSimpleName()));
        }

        return attestationProof;
    }

    private SignatureVerifierContext verifierFromX5CChain(List<String> x5cList, String alg)
            throws GeneralSecurityException, IOException, VerificationException {

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certChain = new ArrayList<>();

        for (String certBase64 : x5cList) {
            byte[] certBytes = Base64.getDecoder().decode(certBase64);
            try (InputStream in = new ByteArrayInputStream(certBytes)) {
                certChain.add((X509Certificate) cf.generateCertificate(in));
            }
        }

        CertPath certPath = cf.generateCertPath(certChain);
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());

        try (InputStream in = new FileInputStream(CACERTS_PATH)) {
            trustStore.load(in, DEFAULT_TRUSTSTORE_PASSWORD);
        }

        Set<TrustAnchor> anchors = new HashSet<>();
        Enumeration<String> aliases = trustStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate cert = trustStore.getCertificate(alias);
            if (cert instanceof X509Certificate x509) {
                anchors.add(new TrustAnchor(x509, null));
            }
        }

        PKIXParameters params = new PKIXParameters(anchors);
        params.setRevocationEnabled(false); // Enable for CRL/OCSP support
        CertPathValidator.getInstance("PKIX").validate(certPath, params);

        X509Certificate leaf = certChain.get(0);
        PublicKey publicKey = leaf.getPublicKey();

        JWK certJwk;
        if (publicKey instanceof RSAPublicKey rsa) {
            certJwk = JWKBuilder.create().algorithm(alg).rsa(rsa, List.of(leaf));
        } else if (publicKey instanceof ECPublicKey ec) {
            certJwk = JWKBuilder.create().algorithm(alg).ec(ec, List.of(leaf), null);
        } else {
            throw new VCIssuerException("Unsupported public key type in certificate chain: " + publicKey.getClass());
        }

        return getVerifier(certJwk, alg);
    }

    private void validateJwsHeader(VCIssuanceContext vcIssuanceContext, JWSHeader header) {
        String alg = Optional.ofNullable(header.getAlgorithm())
                .map(Enum::name)
                .orElseThrow(() -> new VCIssuerException("Missing algorithm in JWS header"));

        List<String> supportedAlgs = Optional.ofNullable(vcIssuanceContext.getCredentialConfig())
                .map(SupportedCredentialConfiguration::getProofTypesSupported)
                .map(ProofTypesSupported::getAttestation)
                .map(ProofTypeMetadata::getProofSigningAlgValuesSupported)
                .orElseThrow(() -> new VCIssuerException("Proof type metadata missing"));

        if (!supportedAlgs.contains(alg)) {
            throw new VCIssuerException("Unsupported signing algorithm: " + alg);
        }

        if (!ATTESTATION_JWT_TYP.equals(header.getType())) {
            throw new VCIssuerException("Invalid JWT typ: expected " + ATTESTATION_JWT_TYP);
        }
    }

    private void validateAttestationPayload(VCIssuanceContext vcIssuanceContext, Map<String, Object> payload)
            throws VCIssuerException, VerificationException {

        if (!payload.containsKey("iat")) {
            throw new VCIssuerException("Missing 'iat' claim in attestation");
        }

        String nonce = Optional.ofNullable(payload.get("nonce"))
                .map(Object::toString)
                .orElseThrow(() -> new VCIssuerException("Missing 'nonce' in attestation"));

        CNonceHandler cNonceHandler = keycloakSession.getProvider(CNonceHandler.class);
        cNonceHandler.verifyCNonce(
                nonce,
                List.of(OID4VCIssuerWellKnownProvider.getCredentialsEndpoint(keycloakSession.getContext())),
                Map.of(
                        JwtCNonceHandler.SOURCE_ENDPOINT,
                        OID4VCIssuerWellKnownProvider.getNonceEndpoint(keycloakSession.getContext())
                )
        );

        // Validate key_storage (optional)
        Object keyStorageClaim = payload.get("key_storage");
        if (keyStorageClaim != null) {
            try {
                ISO18045ResistanceLevel.fromValue(keyStorageClaim.toString());
            } catch (Exception e) {
                throw new VCIssuerException("Invalid 'key_storage' value in attestation: " + keyStorageClaim, e);
            }
        }

        // Validate user_authentication (optional)
        Object userAuthClaim = payload.get("user_authentication");
        if (userAuthClaim != null) {
            try {
                ISO18045ResistanceLevel.fromValue(userAuthClaim.toString());
            } catch (Exception e) {
                throw new VCIssuerException("Invalid 'user_authentication' value in attestation: " + userAuthClaim, e);
            }
        }
    }
}
