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
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.sdjwt.consumer.HttpDataFetcher;

import java.io.IOException;
import java.util.Base64;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Validator for Referenced Token payloads
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-11.html">Token Status List</a>
 */
public class ReferencedTokenValidator {

    private final HttpDataFetcher httpDataFetcher;
    private final ObjectMapper objectMapper;

    public ReferencedTokenValidator(HttpDataFetcher httpDataFetcher) {
        this.httpDataFetcher = httpDataFetcher;
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Validates a Referenced Token payload by checking its status in the status list.
     * status claim is REQUIRED when using the status mechanism.
     *
     * @param tokenPayload The JSON payload of the Referenced Token
     * @throws ReferencedTokenValidationException if validation fails
     */
    public void validate(JsonNode tokenPayload) throws ReferencedTokenValidationException {
        try {
            validateBasicTokenProperties(tokenPayload);

            StatusInfo statusInfo = extractStatusInfo(tokenPayload);

            JsonNode statusListToken = fetchStatusListToken(statusInfo.uri);

            StatusList statusList = extractStatusList(statusListToken);

            int statusValue = readStatusValue(statusList.lst, statusInfo.idx, statusList.bits);

            if (statusValue != 0) { // 0 = VALID, 1 = INVALID, 2 = SUSPENDED, etc.
                throw new ReferencedTokenValidationException(
                        "Token status is not valid. Status value: " + statusValue);
            }

        } catch (Exception e) {
            if (e instanceof ReferencedTokenValidationException) {
                throw e;
            }
            throw new ReferencedTokenValidationException("Failed to validate referenced token", e);
        }
    }

    /**
     * Validates basic token properties including expiration time.
     * This validation should be performed before status list validation.
     *
     * @param tokenPayload The JSON payload of the Referenced Token
     * @throws ReferencedTokenValidationException if basic validation fails
     */
    private void validateBasicTokenProperties(JsonNode tokenPayload) throws ReferencedTokenValidationException {
        // Check for expiration time
        JsonNode exp = tokenPayload.get("exp");
        if (exp != null && exp.isNumber()) {
            long expirationTime = exp.asLong();
            long currentTime = System.currentTimeMillis() / 1000;

            if (currentTime > expirationTime) {
                throw new ReferencedTokenValidationException(
                        "Token has expired. Expiration time: " + expirationTime + ", Current time: " + currentTime);
            }
        }
        // other validations can be added here

    }

    /**
     * Extracts status information from the token payload.
     * According to IETF specification, the status claim is REQUIRED when using the status mechanism.
     *
     * @param tokenPayload The JSON payload of the Referenced Token
     * @return StatusInfo object containing index and URI
     * @throws ReferencedTokenValidationException if status information is missing or malformed
     */
    private StatusInfo extractStatusInfo(JsonNode tokenPayload) throws ReferencedTokenValidationException {
        JsonNode status = tokenPayload.get("status");
        if (status == null) {
            throw new ReferencedTokenValidationException("Missing required 'status' claim in token payload");
        }

        if (!status.isObject()) {
            throw new ReferencedTokenValidationException("'status' claim must be a JSON object");
        }

        JsonNode statusList = status.get("status_list");
        if (statusList == null) {
            throw new ReferencedTokenValidationException("Missing required 'status_list' in status claim");
        }

        if (!statusList.isObject()) {
            throw new ReferencedTokenValidationException("'status_list' must be a JSON object");
        }

        JsonNode idx = statusList.get("idx");
        JsonNode uri = statusList.get("uri");

        if (idx == null) {
            throw new ReferencedTokenValidationException("Missing required 'idx' field in status_list");
        }

        if (uri == null) {
            throw new ReferencedTokenValidationException("Missing required 'uri' field in status_list");
        }

        if (!idx.isNumber()) {
            throw new ReferencedTokenValidationException("'idx' field must be a number");
        }

        if (!uri.isTextual()) {
            throw new ReferencedTokenValidationException("'uri' field must be a string");
        }

        int index = idx.asInt();
        if (index < 0) {
            throw new ReferencedTokenValidationException("'idx' value must be non-negative (got: " + index + ")");
        }

        String uriString = uri.asText();
        if (uriString.trim().isEmpty()) {
            throw new ReferencedTokenValidationException("'uri' value cannot be empty");
        }

        return new StatusInfo(index, uriString);
    }

    /**
     * Fetches the status list token from the specified URI.
     *
     * @param uri The URI to fetch the status list token from
     * @return The status list token as JsonNode
     * @throws ReferencedTokenValidationException if fetching fails
     */
    private JsonNode fetchStatusListToken(String uri) throws ReferencedTokenValidationException {
        try {
            return httpDataFetcher.fetchJsonData(uri);
        } catch (IOException e) {
            throw new ReferencedTokenValidationException("Failed to fetch status list token from: " + uri, e);
        }
    }

    /**
     * Extracts status list information from the status list token.
     *
     * @param statusListToken The status list token as JsonNode
     * @return StatusList object containing bits and lst
     * @throws ReferencedTokenValidationException if extraction fails
     */
    private StatusList extractStatusList(JsonNode statusListToken) throws ReferencedTokenValidationException {
        JsonNode statusList = statusListToken.get("status_list");
        if (statusList == null) {
            throw new ReferencedTokenValidationException("Missing status_list in status list token");
        }

        JsonNode bits = statusList.get("bits");
        JsonNode lst = statusList.get("lst");

        if (bits == null || lst == null) {
            throw new ReferencedTokenValidationException("Missing required status_list fields (bits, lst)");
        }

        if (!bits.isNumber() || !lst.isTextual()) {
            throw new ReferencedTokenValidationException("Invalid status_list field types (bits must be number, lst must be string)");
        }

        return new StatusList(bits.asInt(), lst.asText());
    }

    /**
     * Decodes and decompresses the status list data.
     *
     * @param lst The base64url-encoded, DEFLATE-compressed status list
     * @return The decompressed byte array
     * @throws ReferencedTokenValidationException if decoding/decompression fails
     */
    public static byte[] decodeAndDecompress(String lst) throws ReferencedTokenValidationException {
        try {
            // Add padding if necessary for base64url decoding
            String paddedLst = lst;
            while (paddedLst.length() % 4 != 0) {
                paddedLst += "=";
            }

            // Replace URL-safe characters with standard base64 characters
            paddedLst = paddedLst.replace('-', '+').replace('_', '/');

            // Decode base64
            byte[] compressed = Base64.getDecoder().decode(paddedLst);

            // Decompress using DEFLATE with ZLIB wrapper
            Inflater inflater = new Inflater();
            inflater.setInput(compressed);

            byte[] decompressed = new byte[compressed.length * 10]; // Initial buffer size
            int decompressedLength = inflater.inflate(decompressed);
            inflater.end();

            // Create a new array with the exact size
            byte[] result = new byte[decompressedLength];
            System.arraycopy(decompressed, 0, result, 0, decompressedLength);

            return result;

        } catch (IllegalArgumentException e) {
            throw new ReferencedTokenValidationException("Failed to decode base64url status list", e);
        } catch (DataFormatException e) {
            throw new ReferencedTokenValidationException("Failed to decompress status list", e);
        }
    }

    /**
     * Reads a status value from the status list at the specified index.
     *
     * @param lst  The base64url-encoded, DEFLATE-compressed status list
     * @param idx  The token index to read
     * @param bits The number of bits per status (1, 2, 4, or 8)
     * @return The status value at the given index
     * @throws ReferencedTokenValidationException if the operation fails
     */
    private int readStatusValue(String lst, int idx, int bits) throws ReferencedTokenValidationException {
        byte[] bytes = decodeAndDecompress(lst);
        return readStatusValueFromBytes(bytes, idx, bits);
    }

    /**
     * Helper method to read status value from a byte array.
     *
     * @param bytes The decompressed byte array
     * @param idx   The token index to read
     * @param bits  The number of bits per status (1, 2, 4, or 8)
     * @return The status value at the given index
     * @throws ReferencedTokenValidationException if the operation fails
     */
    public static int readStatusValueFromBytes(byte[] bytes, int idx, int bits) throws ReferencedTokenValidationException {
        if (bits != 1 && bits != 2 && bits != 4 && bits != 8) {
            throw new ReferencedTokenValidationException("Unsupported bits value: " + bits);
        }

        // Calculate total number of entries that can fit in the byte array
        int totalBits = bytes.length * 8;
        int totalEntries = totalBits / bits;

        if (idx < 0 || idx >= totalEntries) {
            throw new ReferencedTokenValidationException(
                    "Index " + idx + " out of range (0-" + (totalEntries - 1) + ")");
        }

        // Calculate the starting bit position for this token
        int startBit = idx * bits;

        // Calculate which byte contains the start of our status value
        int byteIdx = startBit / 8;

        // Calculate the bit position within that byte
        int bitPosInByte = startBit % 8;

        // Create a mask for the number of bits we need to read
        int mask = (1 << bits) - 1;

        // Read the status value
        int statusValue;

        if (bitPosInByte + bits <= 8) {
            // The entire status value fits within one byte
            statusValue = (bytes[byteIdx] >> bitPosInByte) & mask;
        } else {
            // The status value spans across two bytes
            int bitsInFirstByte = 8 - bitPosInByte;
            int bitsInSecondByte = bits - bitsInFirstByte;

            // Read bits from the first byte
            int firstByteValue = (bytes[byteIdx] >> bitPosInByte) & ((1 << bitsInFirstByte) - 1);

            // Read bits from the second byte
            int secondByteValue = (bytes[byteIdx + 1] & ((1 << bitsInSecondByte) - 1)) << bitsInFirstByte;

            // Combine the values
            statusValue = firstByteValue | secondByteValue;
        }

        return statusValue;
    }

    /**
     * Exception thrown when validation fails.
     */
    public static class ReferencedTokenValidationException extends Exception {
        public ReferencedTokenValidationException(String message) {
            super(message);
        }

        public ReferencedTokenValidationException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Internal class to hold status information.
     */
    private static class StatusInfo {
        final int idx;
        final String uri;

        StatusInfo(int idx, String uri) {
            this.idx = idx;
            this.uri = uri;
        }
    }

    /**
     * Internal class to hold status list information.
     */
    private static class StatusList {
        final int bits;
        final String lst;

        StatusList(int bits, String lst) {
            this.bits = bits;
            this.lst = lst;
        }
    }
}
