package org.keycloak.protocol.oid4vc.issuance.keybinding;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProvider;
import org.keycloak.protocol.oid4vc.issuance.VCIssuanceContext;
import org.keycloak.protocol.oid4vc.issuance.VCIssuerException;
import org.keycloak.protocol.oid4vc.model.AttestationProof;
import org.keycloak.protocol.oid4vc.model.Proof;
import org.keycloak.protocol.oid4vc.model.ProofType;
import org.keycloak.protocol.oid4vc.model.ProofTypeMetadata;
import org.keycloak.protocol.oid4vc.model.ProofTypesSupported;
import org.keycloak.protocol.oid4vc.model.SupportedCredentialConfiguration;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Validates attestation proofs as per OID4VCI specification.
 */
public class AttestationProofValidator extends AbstractProofValidator {

    private static final String ATTESTATION_JWT_TYP = "keyattestation+jwt";

    public AttestationProofValidator(KeycloakSession session) {
        super(session);
    }

    @Override
    public List<JWK> validateProof(VCIssuanceContext vcIssuanceContext) throws VCIssuerException {
        try {
            return validateAttestationProof(vcIssuanceContext);
        } catch (JWSInputException | VerificationException | IOException e) {
            throw new VCIssuerException("Could not validate attestation proof", e);
        }
    }

    private List<JWK> validateAttestationProof(VCIssuanceContext vcIssuanceContext) throws JWSInputException, VerificationException, IOException {
        Optional<Proof> optionalProof = getProofFromContext(vcIssuanceContext);
        if (optionalProof.isEmpty() || !(optionalProof.get() instanceof AttestationProof)) {
            return List.of(); // No proof or wrong type
        }

        AttestationProof proof = (AttestationProof) optionalProof.get();
        String attestationJwt = proof.getAttestation();
        if (attestationJwt == null) {
            throw new VCIssuerException("Attestation JWT is null");
        }

        JWSInput jwsInput = new JWSInput(attestationJwt);
        JWSHeader jwsHeader = jwsInput.getHeader();
        validateJwsHeader(vcIssuanceContext, jwsHeader);

        // Verify signature using trusted keys
        SignatureVerifierContext verifier = getTrustedVerifier(jwsHeader);
        if (!verifier.verify(jwsInput.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8), jwsInput.getSignature())) {
            throw new VCIssuerException("Invalid attestation signature");
        }

        // Validate payload
        Map<String, Object> payload = JsonSerialization.mapper.readValue(jwsInput.getContent(), Map.class);
        validateAttestationPayload(vcIssuanceContext, payload);

        // Extract attested_keys
        List<Map<String, Object>> attestedKeys = (List<Map<String, Object>>) payload.get("attested_keys");
        if (attestedKeys == null || attestedKeys.isEmpty()) {
            throw new VCIssuerException("No attested_keys in attestation");
        }

        List<JWK> jwks = new ArrayList<>();
        for (Map<String, Object> keyMap : attestedKeys) {
            JWK jwk = JsonSerialization.mapper.convertValue(keyMap, JWK.class);
            jwks.add(jwk);
        }

        return jwks;
    }

    private void validateJwsHeader(VCIssuanceContext vcIssuanceContext, JWSHeader jwsHeader) throws VCIssuerException {
        Optional.ofNullable(jwsHeader.getAlgorithm())
                .orElseThrow(() -> new VCIssuerException("Missing algorithm in attestation header"));

        Optional.ofNullable(vcIssuanceContext.getCredentialConfig())
                .map(SupportedCredentialConfiguration::getProofTypesSupported)
                .map(ProofTypesSupported::getAttestation)
                .map(ProofTypeMetadata::getProofSigningAlgValuesSupported)
                .filter(algs -> algs.contains(jwsHeader.getAlgorithm().name()))
                .orElseThrow(() -> new VCIssuerException("Unsupported attestation algorithm: " + jwsHeader.getAlgorithm().name()));

        Optional.ofNullable(jwsHeader.getType())
                .filter(ATTESTATION_JWT_TYP::equals)
                .orElseThrow(() -> new VCIssuerException("Attestation JWT type must be: " + ATTESTATION_JWT_TYP));
    }

    private void validateAttestationPayload(VCIssuanceContext vcIssuanceContext, Map<String, Object> payload) throws VCIssuerException, VerificationException {
        // Validate iat
        Optional.ofNullable(payload.get("iat"))
                .orElseThrow(() -> new VCIssuerException("Missing iat claim in attestation"));

        // Validate c_nonce
        String nonce = (String) payload.get("nonce");
        CNonceHandler cNonceHandler = keycloakSession.getProvider(CNonceHandler.class);
        cNonceHandler.verifyCNonce(nonce,
                List.of(OID4VCIssuerWellKnownProvider.getCredentialsEndpoint(keycloakSession.getContext())),
                Map.of(JwtCNonceHandler.SOURCE_ENDPOINT,
                        OID4VCIssuerWellKnownProvider.getNonceEndpoint(keycloakSession.getContext())));
    }

    private SignatureVerifierContext getTrustedVerifier(JWSHeader jwsHeader) throws VCIssuerException {
        // Assume a KeyAttestationTrustStore provider exists
        KeyAttestationTrustStore trustStore = keycloakSession.getProvider(KeyAttestationTrustStore.class);
        if (trustStore == null) {
            throw new VCIssuerException("No key attestation trust store configured");
        }
        return trustStore.getVerifier(jwsHeader.getAlgorithm().name())
                .orElseThrow(() -> new VCIssuerException("No trusted verifier for algorithm: " + jwsHeader.getAlgorithm().name()));
    }

    private Optional<Proof> getProofFromContext(VCIssuanceContext vcIssuanceContext) throws VCIssuerException {
        return Optional.ofNullable(vcIssuanceContext.getCredentialConfig())
                .map(SupportedCredentialConfiguration::getProofTypesSupported)
                .flatMap(proofTypes -> {
                    Optional.ofNullable(proofTypes.getAttestation())
                            .orElseThrow(() -> new VCIssuerException("Attestation proof type not supported"));
                    Proof proof = vcIssuanceContext.getCredentialRequest().getProof();
                    if (proof == null || !ProofType.ATTESTATION.equals(proof.getProofType())) {
                        throw new VCIssuerException("Expected attestation proof type");
                    }
                    return Optional.of(proof);
                });
    }
}
