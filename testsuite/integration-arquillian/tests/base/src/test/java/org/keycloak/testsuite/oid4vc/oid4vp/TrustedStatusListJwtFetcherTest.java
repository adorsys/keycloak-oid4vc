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

package org.keycloak.testsuite.oid4vc.oid4vp;

import org.junit.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.tokenstatus.http.TrustedStatusListJwtFetcher;
import org.keycloak.sdjwt.TestUtils;
import org.keycloak.testsuite.oid4vc.issuance.signing.OID4VCIssuerEndpointTest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Test trust enforcement of retrieved status list JWTs.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class TrustedStatusListJwtFetcherTest extends OID4VCIssuerEndpointTest {

    @Test
    public void shouldAcceptTrustedStatusListJwts() {
        String statusListJwt = exampleValidStatusListJwt();
        testingClient.server(TEST_REALM_NAME).run(session -> {
            try {
                var fetcher = mockFetcher(session, statusListJwt);
                String fetchedJwt = fetcher.fetchStatusListJwt("https://example.com/status-list-jwt");
                assertEquals(statusListJwt, fetchedJwt);
            } catch (Exception e) {
                fail("Operation should not fail");
            }
        });
    }

    @Test
    public void shouldRejectNonHttpsURIs() {
        String statusListJwt = exampleValidStatusListJwt();
        testingClient.server(TEST_REALM_NAME).run(session -> {
            try {
                var fetcher = mockFetcher(session, statusListJwt);
                fetcher.fetchStatusListJwt("http://example.com/status-list-jwt");
                fail("Operation should fail");
            } catch (Exception e) {
                assertTrue(e.getMessage().startsWith("Status list JWT URI must use HTTPS:"));
            }
        });
    }

    @Test
    public void shouldRejectInvalidStatusListJwts_InvalidSignature() {
        shouldRejectInvalidStatusListJwt(
                "status-list-jwt+invalid-signature.txt",
                "Error during JWS signature verification",
                "Invalid JWS signature"
        );
    }

    @Test
    public void shouldRejectInvalidStatusListJwts_NoX5C() {
        shouldRejectInvalidStatusListJwt(
                "status-list-jwt+no-x5c.txt",
                "Could extract verifier from X5C certificate chain",
                "Missing or empty x5c header in JWS"
        );
    }

    private void shouldRejectInvalidStatusListJwt(
            String testVector,
            String expectedErrorMessage,
            String expectedCauseMessage
    ) {
        String statusListJwt = exampleStatusListJwt(testVector);
        testingClient.server(TEST_REALM_NAME).run(session -> {
            try {
                var fetcher = mockFetcher(session, statusListJwt);
                fetcher.fetchStatusListJwt("https://example.com/status-list-jwt");
                fail("Operation should fail");
            } catch (Exception e) {
                assertEquals(expectedErrorMessage, e.getMessage());
                assertEquals(expectedCauseMessage, e.getCause().getMessage());
            }
        });
    }

    static TrustedStatusListJwtFetcher mockFetcher(KeycloakSession session, String statusListJwt) {
        return new MockTrustedStatusListJwtFetcher(session, statusListJwt);
    }

    static String exampleValidStatusListJwt() {
        return exampleStatusListJwt("status-list-jwt.txt");
    }

    static String exampleStatusListJwt(String filename) {
        return TestUtils.readFileAsString(
                TrustedStatusListJwtFetcherTest.class,
                "oid4vc/tokenstatus/" + filename
        );
    }

    static class MockTrustedStatusListJwtFetcher extends TrustedStatusListJwtFetcher {

        private final String mockedStatusListJwt;

        public MockTrustedStatusListJwtFetcher(KeycloakSession session, String mockedStatusListJwt) {
            super(session);
            this.mockedStatusListJwt = mockedStatusListJwt;
        }

        @Override
        protected String _fetchStatusListJwt(String uri) {
            return mockedStatusListJwt;
        }
    }
}
