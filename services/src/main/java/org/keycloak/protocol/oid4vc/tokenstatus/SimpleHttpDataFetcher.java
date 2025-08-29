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

package org.keycloak.protocol.oid4vc.tokenstatus;

import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sdjwt.consumer.HttpDataFetcher;
import org.keycloak.broker.provider.util.SimpleHttp;

import java.io.IOException;

/**
 * Simple implementation of HttpDataFetcher for token status list validation.
 */
public class SimpleHttpDataFetcher implements HttpDataFetcher {

    /**
     * Accept header value for Status List JWT format.
     * Used when requesting Status List Tokens from status list servers.
     */
    public static final String STATUS_LIST_JWT_ACCEPT_HEADER = "application/statuslist+jwt";

    private final KeycloakSession session;

    public SimpleHttpDataFetcher(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public JsonNode fetchJsonData(String uri) throws IOException {
        return SimpleHttp.doGet(uri, session)
                .header("Accept", STATUS_LIST_JWT_ACCEPT_HEADER)
                .asJson();
    }
}
