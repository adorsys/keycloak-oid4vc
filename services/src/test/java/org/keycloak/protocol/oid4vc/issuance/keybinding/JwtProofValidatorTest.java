package org.keycloak.protocol.oid4vc.issuance.keybinding;

import java.util.HashMap;
import java.util.Map;

import org.keycloak.protocol.oid4vc.issuance.VCIssuerException;
import org.keycloak.utils.AbstractUtilSessionTest;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class JwtProofValidatorTest extends AbstractUtilSessionTest {

    @Test
    public void testValidateNoPrivateKeyInHeaderClaims_RS256_Blocked() {
        JwtProofValidator validator = new JwtProofValidator(session, null);
        Map<String, Object> headerClaims = new HashMap<>();
        Map<String, Object> jwk = new HashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("d", "secret");
        headerClaims.put("jwk", jwk);
        
        assertThrows(VCIssuerException.class, () -> validator.validateNoPrivateKeyInHeaderClaims("RS256", headerClaims));
    }

    @Test
    public void testValidateNoPrivateKeyInHeaderClaims_RS256_Allowed() {
        JwtProofValidator validator = new JwtProofValidator(session, null);
        Map<String, Object> headerClaims = new HashMap<>();
        Map<String, Object> jwk = new HashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("n", "modulus");
        jwk.put("e", "exponent");
        headerClaims.put("jwk", jwk);
        
        assertDoesNotThrow(() -> validator.validateNoPrivateKeyInHeaderClaims("RS256", headerClaims));
    }

    @Test
    public void testValidateNoPrivateKeyInHeaderClaims_ES256_Blocked() {
        JwtProofValidator validator = new JwtProofValidator(session, null);
        Map<String, Object> headerClaims = new HashMap<>();
        Map<String, Object> jwk = new HashMap<>();
        jwk.put("kty", "EC");
        jwk.put("d", "secret");
        headerClaims.put("jwk", jwk);
        
        assertThrows(VCIssuerException.class, () -> validator.validateNoPrivateKeyInHeaderClaims("ES256", headerClaims));
    }

    @Test
    public void testValidateNoPrivateKeyInHeaderClaims_ES256_Allowed() {
        JwtProofValidator validator = new JwtProofValidator(session, null);
        Map<String, Object> headerClaims = new HashMap<>();
        Map<String, Object> jwk = new HashMap<>();
        jwk.put("kty", "EC");
        jwk.put("x", "coord-x");
        jwk.put("y", "coord-y");
        headerClaims.put("jwk", jwk);
        
        assertDoesNotThrow(() -> validator.validateNoPrivateKeyInHeaderClaims("ES256", headerClaims));
    }

    @Test
    public void testValidateNoPrivateKeyInHeaderClaims_UnknownAlgorithm_FallbackBlocked() {
        JwtProofValidator validator = new JwtProofValidator(session, null);
        Map<String, Object> headerClaims = new HashMap<>();
        Map<String, Object> jwk = new HashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("d", "secret");
        headerClaims.put("jwk", jwk);
        
        // FAKE256 should trigger the fallback which includes "d"
        assertThrows(VCIssuerException.class, () -> validator.validateNoPrivateKeyInHeaderClaims("FAKE256", headerClaims));
    }
}
