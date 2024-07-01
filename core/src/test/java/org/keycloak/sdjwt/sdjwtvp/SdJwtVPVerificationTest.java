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

package org.keycloak.sdjwt.sdjwtvp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.ClassRule;
import org.junit.Test;
import org.keycloak.common.VerificationException;
import org.keycloak.rule.CryptoInitRule;
import org.keycloak.sdjwt.IssuerSignedJwtVerificationOpts;
import org.keycloak.sdjwt.SdJwt;
import org.keycloak.sdjwt.TestSettings;
import org.keycloak.sdjwt.TestUtils;
import org.keycloak.sdjwt.vp.KeyBindingJWT;
import org.keycloak.sdjwt.vp.KeyBindingJwtVerificationOpts;
import org.keycloak.sdjwt.vp.SdJwtVP;

import java.time.Instant;
import java.util.List;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

/**
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public abstract class SdJwtVPVerificationTest {

    @ClassRule
    public static CryptoInitRule cryptoInitRule = new CryptoInitRule();

    static ObjectMapper mapper = new ObjectMapper();
    static TestSettings testSettings = TestSettings.getInstance();

    @Test
    public void testVerif_s20_1_sdjwt_with_kb() throws VerificationException {
        String sdJwtVPString = TestUtils.readFileAsString(getClass(), "sdjwt/s20.1-sdjwt+kb.txt");
        SdJwtVP sdJwtVP = SdJwtVP.of(sdJwtVPString);

        sdJwtVP.verify(
                defaultIssuerSignedJwtVerificationOpts().build(),
                defaultKeyBindingJwtVerificationOpts().build()
        );
    }

    @Test
    public void testVerif_s20_8_sdjwt_with_kb__AltCnfCurves() throws VerificationException {
        var entries = List.of("sdjwt/s20.8-sdjwt+kb--es384.txt", "sdjwt/s20.8-sdjwt+kb--es512.txt");

        for (var entry: entries) {
            String sdJwtVPString = TestUtils.readFileAsString(getClass(), entry);
            SdJwtVP sdJwtVP = SdJwtVP.of(sdJwtVPString);

            sdJwtVP.verify(
                    defaultIssuerSignedJwtVerificationOpts().build(),
                    defaultKeyBindingJwtVerificationOpts().build()
            );
        }
    }

    @Test
    public void testVerifKeyBindingNotRequired() throws VerificationException {
        String sdJwtVPString = TestUtils.readFileAsString(getClass(), "sdjwt/s6.2-presented-sdjwtvp.txt");
        SdJwtVP sdJwtVP = SdJwtVP.of(sdJwtVPString);

        sdJwtVP.verify(
                defaultIssuerSignedJwtVerificationOpts().build(),
                defaultKeyBindingJwtVerificationOpts()
                        .withKeyBindingRequired(false)
                        .build()
        );
    }

    @Test
    public void testShouldFail_IfExtraDisclosureWithNoDigest() {
        testShouldFailGeneric(
                // One disclosure has no digest throughout Issuer-signed JWT
                "sdjwt/s20.6-sdjwt+kb--disclosure-with-no-digest.txt",
                defaultKeyBindingJwtVerificationOpts().build(),
                "At least one disclosure is not protected by digest",
                null
        );
    }

    @Test
    public void testShouldFail_IfFieldDisclosureLengthIncorrect() {
        testShouldFailGeneric(
                // One field disclosure has only two elements
                "sdjwt/s20.7-sdjwt+kb--invalid-field-disclosure.txt",
                defaultKeyBindingJwtVerificationOpts().build(),
                "A field disclosure must contain exactly three elements",
                null
        );
    }

    @Test
    public void testShouldFail_IfArrayElementDisclosureLengthIncorrect() {
        testShouldFailGeneric(
                // One array element disclosure has more than two elements
                "sdjwt/s20.7-sdjwt+kb--invalid-array-elt-disclosure.txt",
                defaultKeyBindingJwtVerificationOpts().build(),
                "An array element disclosure must contain exactly two elements",
                null
        );
    }

    @Test
    public void testShouldFail_IfKeyBindingRequiredAndMissing() {
        testShouldFailGeneric(
                // This sd-jwt has no key binding jwt
                "sdjwt/s6.2-presented-sdjwtvp.txt",
                defaultKeyBindingJwtVerificationOpts()
                        .withKeyBindingRequired(true)
                        .build(),
                "Missing Key Binding JWT",
                null
        );
    }

    @Test
    public void testShouldFail_IfKeyBindingJwtSignatureInvalid() {
        testShouldFailGeneric(
                // Messed up with the kb signature
                "sdjwt/s20.1-sdjwt+kb--wrong-kb-signature.txt",
                defaultKeyBindingJwtVerificationOpts().build(),
                "Key binding JWT invalid",
                "VerificationException: Invalid jws signature"
        );
    }

    @Test
    public void testShouldFail_IfNoCnfClaim() {
        testShouldFailGeneric(
                // This test vector has no cnf claim in Issuer-signed JWT
                "sdjwt/s20.2-sdjwt+kb--no-cnf-claim.txt",
                defaultKeyBindingJwtVerificationOpts().build(),
                "No cnf claim in Issuer-signed JWT for key binding",
                null
        );
    }

    @Test
    public void testShouldFail_IfWrongKbTyp() {
        testShouldFailGeneric(
                // Key Binding JWT's header: {"kid": "holder", "typ": "unexpected",  "alg": "ES256"}
                "sdjwt/s20.3-sdjwt+kb--wrong-kb-typ.txt",
                defaultKeyBindingJwtVerificationOpts().build(),
                "Key Binding JWT is not of declared typ kb+jwt",
                null
        );
    }

    @Test
    public void testShouldFail_IfReplayChecksFail_Nonce() {
        testShouldFailGeneric(
                "sdjwt/s20.1-sdjwt+kb.txt",
                defaultKeyBindingJwtVerificationOpts()
                        .withNonce("abcd") // kb's nonce is "1234567890"
                        .build(),
                "Key binding JWT: Unexpected `nonce` value",
                null
        );
    }

    @Test
    public void testShouldFail_IfReplayChecksFail_Aud() {
        testShouldFailGeneric(
                "sdjwt/s20.1-sdjwt+kb.txt",
                defaultKeyBindingJwtVerificationOpts()
                        .withAud("abcd") // kb's aud is "https://verifier.example.org"
                        .build(),
                "Key binding JWT: Unexpected `aud` value",
                null
        );
    }

    @Test
    public void testShouldFail_IfKbSdHashWrongFormat() {
        var kbPayload = exampleS20KbPayload();

        // This hash is not a string
        kbPayload.set("sd_hash", mapper.valueToTree(1234));

        testShouldFailGenericS20(
                kbPayload,
                defaultKeyBindingJwtVerificationOpts().build(),
                "Key binding JWT: Claim `sd_hash` missing or not a string",
                null
        );
    }

    @Test
    public void testShouldFail_IfKbSdHashInvalid() {
        var kbPayload = exampleS20KbPayload();

        // This hash makes no sense
        kbPayload.put("sd_hash", "c3FmZHFmZGZlZXNkZmZi");

        testShouldFailGenericS20(
                kbPayload,
                defaultKeyBindingJwtVerificationOpts().build(),
                "Key binding JWT: Invalid `sd_hash` digest",
                null
        );
    }

    @Test
    public void testShouldFail_IfKbIssuedInFuture() {
        long now = Instant.now().getEpochSecond();

        var kbPayload = exampleS20KbPayload();
        kbPayload.set("iat", mapper.valueToTree(now + 1000));

        testShouldFailGenericS20(
                kbPayload,
                defaultKeyBindingJwtVerificationOpts().build(),
                "Key binding JWT: Invalid `iat` claim",
                "jwt issued in the future"
        );
    }

    @Test
    public void testShouldFail_IfKbTooOld() {
        long issuerSignedJwtIat = 1683000000; // same value in test vector

        var kbPayload = exampleS20KbPayload();
        // This KB-JWT is then issued more than 60s ago
        kbPayload.set("iat", mapper.valueToTree(issuerSignedJwtIat - 120));

        testShouldFailGenericS20(
                kbPayload,
                defaultKeyBindingJwtVerificationOpts()
                        .withAllowedMaxAge(60)
                        .build(),
                "Key binding JWT is too old",
                null
        );
    }

    @Test
    public void testShouldFail_IfKbExpired() {
        long now = Instant.now().getEpochSecond();

        var kbPayload = exampleS20KbPayload();
        kbPayload.set("exp", mapper.valueToTree(now - 1000));

        testShouldFailGenericS20(
                kbPayload,
                defaultKeyBindingJwtVerificationOpts()
                        .withValidateExpirationClaim(true)
                        .build(),
                "Key binding JWT: Invalid `exp` claim",
                "jwt has expired"
        );
    }

    @Test
    public void testShouldFail_IfKbNotBeforeTimeYet() {
        long now = Instant.now().getEpochSecond();

        var kbPayload = exampleS20KbPayload();
        kbPayload.set("nbf", mapper.valueToTree(now + 1000));

        testShouldFailGenericS20(
                kbPayload,
                defaultKeyBindingJwtVerificationOpts()
                        .withValidateNotBeforeClaim(true)
                        .build(),
                "Key binding JWT: Invalid `nbf` claim",
                "jwt not valid yet"
        );
    }

    @Test
    public void testShouldFail_IfCnfNotJwk() {
        // The cnf claim is not of type jwk
        String sdJwtVPString = TestUtils.readFileAsString(getClass(), "sdjwt/s20.8-sdjwt+kb--cnf-is-not-jwk.txt");
        SdJwtVP sdJwtVP = SdJwtVP.of(sdJwtVPString);

        var exception = assertThrows(
                UnsupportedOperationException.class,
                () -> sdJwtVP.verify(
                        defaultIssuerSignedJwtVerificationOpts().build(),
                        defaultKeyBindingJwtVerificationOpts().build()
                )
        );

        assertEquals("Only cnf/jwk claim supported", exception.getMessage());
    }

    @Test
    public void testShouldFail_IfCnfJwkCantBeParsed() {
        testShouldFailGeneric(
                // The cnf/jwk object has an unrecognized key type
                "sdjwt/s20.8-sdjwt+kb--cnf-jwk-is-malformed.txt",
                defaultKeyBindingJwtVerificationOpts().build(),
                "Malformed or unsupported cnf/jwk claim",
                null
        );
    }

    @Test
    public void testShouldFail_IfCnfJwkCantBeParsed2() {
        testShouldFailGeneric(
                // HMAC cnf/jwk parsing is not supported
                "sdjwt/s20.8-sdjwt+kb--cnf-hmac.txt",
                defaultKeyBindingJwtVerificationOpts().build(),
                "Malformed or unsupported cnf/jwk claim",
                null
        );
    }

    @Test
    public void testShouldFail_IfCnfJwkAlgNotSupported() {
        testShouldFailGeneric(
                // RSA cnf/jwk are not supported
                "sdjwt/s20.8-sdjwt+kb--cnf-rsa.txt",
                defaultKeyBindingJwtVerificationOpts().build(),
                "cnf/jwk alg is unsupported or deemed not secure",
                null
        );
    }

    private void testShouldFailGeneric(
            String testFilePath,
            KeyBindingJwtVerificationOpts keyBindingJwtVerificationOpts,
            String exceptionMessage,
            String exceptionCauseMessage
    ) {
        String sdJwtVPString = TestUtils.readFileAsString(getClass(), testFilePath);
        SdJwtVP sdJwtVP = SdJwtVP.of(sdJwtVPString);

        var exception = assertThrows(
                VerificationException.class,
                () -> sdJwtVP.verify(
                        defaultIssuerSignedJwtVerificationOpts().build(),
                        keyBindingJwtVerificationOpts
                )
        );

        assertEquals(exceptionMessage, exception.getMessage());
        if (exceptionCauseMessage != null) {
            assertThat(exception.getCause().getMessage(), containsString(exceptionCauseMessage));
        }
    }

    private void testShouldFailGenericS20(
            JsonNode kbPayloadSubstitute,
            KeyBindingJwtVerificationOpts keyBindingJwtVerificationOpts,
            String exceptionMessage,
            String exceptionCauseMessage
    ) {
        KeyBindingJWT keyBindingJWT = KeyBindingJWT.from(
                kbPayloadSubstitute,
                testSettings.holderSigContext,
                KeyBindingJWT.TYP
        );

        String sdJwtVPString = TestUtils.readFileAsString(getClass(), "sdjwt/s20.1-sdjwt+kb.txt");
        SdJwtVP sdJwtVP = SdJwtVP.of(
                sdJwtVPString.substring(0, sdJwtVPString.lastIndexOf(SdJwt.DELIMITER) + 1)
                        + keyBindingJWT.toJws()
        );

        var exception = assertThrows(
                VerificationException.class,
                () -> sdJwtVP.verify(
                        defaultIssuerSignedJwtVerificationOpts().build(),
                        keyBindingJwtVerificationOpts
                )
        );

        assertEquals(exceptionMessage, exception.getMessage());
        if (exceptionCauseMessage != null) {
            assertEquals(exceptionCauseMessage, exception.getCause().getMessage());
        }
    }

    private IssuerSignedJwtVerificationOpts.Builder defaultIssuerSignedJwtVerificationOpts() {
        return IssuerSignedJwtVerificationOpts.builder()
                .withVerifier(testSettings.issuerVerifierContext)
                .withValidateIssuedAtClaim(false)
                .withValidateNotBeforeClaim(false);
    }

    private KeyBindingJwtVerificationOpts.Builder defaultKeyBindingJwtVerificationOpts() {
        return KeyBindingJwtVerificationOpts.builder()
                .withKeyBindingRequired(true)
                .withAllowedMaxAge(Integer.MAX_VALUE)
                .withNonce("1234567890")
                .withAud("https://verifier.example.org")
                .withValidateExpirationClaim(false)
                .withValidateNotBeforeClaim(false);
    }

    private ObjectNode exampleS20KbPayload() {
        var payload = mapper.createObjectNode();
        payload.put("nonce", "1234567890");
        payload.put("aud", "https://verifier.example.org");
        payload.put("sd_hash", "X9RrrfWt_70gHzOcovGSIt4Fms9Tf2g2hjlWVI_cxZg");
        payload.set("iat", mapper.valueToTree(1702315679));

        return payload;
    }
}
