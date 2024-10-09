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
import org.keycloak.sdjwt.SdJwtUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class HttpClient {

    // Helper method to fetch data using HttpURLConnection and parse JSON
    public JsonNode fetchJsonData(String uri) throws IOException {
        HttpURLConnection connection = null;

        try {
            // Create URL object
            URL url = new URL(uri);

            // Open connection
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Accept", "application/json");

            // Check if response code is 200 (OK)
            int responseCode = connection.getResponseCode();
            if (responseCode != 200) {
                throw new IOException("Failed to fetch data. HTTP error code: " + responseCode);
            }

            // Read the response as a string
            String payload = parseInputStream(url.openStream());

            // Parse the JSON response into a JsonNode
            return SdJwtUtils.mapper.readTree(payload);
        } finally {
            // Clean up resources
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private String parseInputStream(InputStream inputStream) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        StringBuilder response = new StringBuilder();

        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }

        reader.close(); // Close the reader after use
        return response.toString();
    }
}
