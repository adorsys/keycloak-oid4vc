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

package org.keycloak.sdjwt.consumer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.JwkParsingUtils;
import org.keycloak.sdjwt.SdJwtUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A trusted Issuer for running SD-JWT VP verification.
 *
 * <p>
 * This implementation targets issuers exposing verifying keys on a normalized JWT VC Issuer metadata endpoint.
 * </p>
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-05#name-issuer-signed-jwt-verificat">
 * JWT VC Issuer Metadata
 * </a>
 */
public class JwtVcMetadataTrustedSdJwtIssuer implements TrustedSdJwtIssuer {

    private static final String JWT_VC_ISSUER_END_POINT = "/.well-known/jwt-vc-issuer";
    private static final HttpClient httpClient = HttpClient.newBuilder().build();

    private final Pattern issuerUriPattern;

    /**
     * @param issuerUri a trusted issuer URI
     */
    public JwtVcMetadataTrustedSdJwtIssuer(String issuerUri) {
        try {
            validateHttpsIssuerUri(issuerUri);
        } catch (VerificationException e) {
            throw new IllegalArgumentException(e);
        }

        // Build a Regex pattern to only match the argument URI
        this.issuerUriPattern = Pattern.compile(Pattern.quote(issuerUri));
    }

    /**
     * @param issuerUriPattern a regex pattern for trusted issuer URIs
     */
    public JwtVcMetadataTrustedSdJwtIssuer(Pattern issuerUriPattern) {
        this.issuerUriPattern = issuerUriPattern;
    }

    @Override
    public List<SignatureVerifierContext> resolveIssuerVerifyingKeys(IssuerSignedJWT issuerSignedJWT)
            throws VerificationException {
        // Read iss (claim) and kid (header)
        String iss = Optional.ofNullable(issuerSignedJWT.getPayload().get("iss"))
                .map(JsonNode::asText)
                .orElse("");
        String kid = issuerSignedJWT.getHeader().getKeyId();

        // Match the read iss claim against the trusted pattern
        Matcher matcher = issuerUriPattern.matcher(iss);
        if (!matcher.matches()) {
            throw new VerificationException(String.format(
                    "Unexpected Issuer URI claim. Expected=/%s/, Got=%s",
                    issuerUriPattern.pattern(), iss
            ));
        }

        // As per specs, only HTTPS URIs are supported
        validateHttpsIssuerUri(iss);

        // Fetch and collect exposed JWKs
        List<JsonNode> jwks = new ArrayList<>();
        for (var jwk : fetchIssuerMetadata(iss)) {
            jwks.add(jwk);
        }

        // If kid specified, only consider matching keys
        if (kid != null) {
            jwks = jwks.stream().filter(jwk -> {
                var jwkKid = jwk.get("kid");
                return jwkKid != null && jwkKid.asText().equals(kid);
            }).toList();

            if (jwks.isEmpty()) {
                throw new VerificationException("No matching JWK found for kid: " + kid);
            }
        }

        // Build JWSVerifier's
        var verifiers = new ArrayList<SignatureVerifierContext>();
        for (var jwk : jwks) {
            try {
                verifiers.add(JwkParsingUtils.convertJwkToVerifierContext(jwk));
            } catch (Exception e) {
                throw new VerificationException("A potential JWK was retrieved but found invalid");
            }
        }

        return verifiers;
    }

    private void validateHttpsIssuerUri(String issuerUri) throws VerificationException {
        if (!issuerUri.startsWith("https://")) {
            throw new VerificationException(
                    "HTTPS URI required to retrieve JWT VC Issuer Metadata"
            );
        }
    }

    private ArrayNode fetchIssuerMetadata(String issuerUri) throws VerificationException {
        String jwtVcIssuerUri = issuerUri
                .replaceAll("/$", "") // Remove any trailing slash
                .concat(JWT_VC_ISSUER_END_POINT); // Append well-known path

        JsonNode issuerMetadata = fetchData(jwtVcIssuerUri);
        JsonNode jwksUri, jwks = null;

        if (issuerMetadata != null) {
            jwksUri = issuerMetadata.get("jwks_uri");
            jwks = issuerMetadata.get("jwks");

            if (jwksUri != null) {
                jwks = fetchData(jwksUri.textValue());
            }
        }

        if (jwks == null || jwks.get("keys") == null || !jwks.get("keys").isArray()) {
            throw new VerificationException(
                    String.format("Could not resolve issuer JWKs with URI: %s", issuerUri));
        }

        return (ArrayNode) jwks.get("keys");
    }

    // Helper method to fetch data using HttpClient and parse JSON
    private JsonNode fetchData(String uri) throws VerificationException {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(new URI(uri))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                return SdJwtUtils.mapper.readTree(response.body());
            } else {
                throw new VerificationException(String.format(
                        "Failed to fetch data from URI %s with status code %s",
                        uri, response.statusCode()
                ));
            }
        } catch (URISyntaxException | InterruptedException e) {
            throw new VerificationException(
                    "Error occurred while fetching data from URI: " + uri, e
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
