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
package org.keycloak.protocol.oid4vc.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.protocol.oid4vc.model.ClaimsDescription;

import java.util.ArrayList;
import java.util.List;

/**
 * Utility class for handling claims path pointers.
 * A claims path pointer is a pointer into the Verifiable Credential, identifying one or more claims.
 */
public class ClaimsPathPointer {

    private static final Logger logger = Logger.getLogger(ClaimsPathPointer.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Validates a claims path pointer.
     *
     * @param path the claims path pointer to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValidPath(List<Object> path) {
        if (path == null || path.isEmpty()) {
            return false;
        }

        for (Object component : path) {
            if (component == null) {
                // null is valid for array selection
                continue;
            }

            if (component instanceof String) {
                // String is valid for object key selection
                continue;
            }

            if (component instanceof Integer) {
                Integer index = (Integer) component;
                if (index < 0) {
                    // Negative integers are not allowed
                    return false;
                }
                // Non-negative integers are valid for array index selection
                continue;
            }

            // Any other type is invalid
            return false;
        }

        return true;
    }

    /**
     * Validates a list of claims descriptions for conflicts and contradictions.
     *
     * @param claims the list of claims descriptions to validate
     * @return true if valid, false if conflicts are found
     */
    public static boolean validateClaimsDescriptions(List<ClaimsDescription> claims) {
        if (claims == null || claims.isEmpty()) {
            return true;
        }

        // Check for repeated or contradictory claim descriptions
        for (int i = 0; i < claims.size(); i++) {
            for (int j = i + 1; j < claims.size(); j++) {
                ClaimsDescription claim1 = claims.get(i);
                ClaimsDescription claim2 = claims.get(j);

                if (isConflicting(claim1, claim2)) {
                    logger.warnf("Conflicting claims descriptions found: %s and %s", claim1.getPath(), claim2.getPath());
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Checks if two claims descriptions are conflicting.
     *
     * @param claim1 first claims description
     * @param claim2 second claims description
     * @return true if conflicting, false otherwise
     */
    private static boolean isConflicting(ClaimsDescription claim1, ClaimsDescription claim2) {
        List<Object> path1 = claim1.getPath();
        List<Object> path2 = claim2.getPath();

        if (path1 == null || path2 == null) {
            return false;
        }

        // Check if paths are identical (same claim addressed)
        if (path1.equals(path2)) {
            return true;
        }

        // Check for array vs object conflicts
        return hasArrayObjectConflict(path1, path2);
    }

    /**
     * Checks if there's a conflict between array and object addressing for the same claim.
     *
     * @param path1 first path
     * @param path2 second path
     * @return true if there's an array/object conflict, false otherwise
     */
    private static boolean hasArrayObjectConflict(List<Object> path1, List<Object> path2) {
        int minLength = Math.min(path1.size(), path2.size());

        for (int i = 0; i < minLength; i++) {
            Object comp1 = path1.get(i);
            Object comp2 = path2.get(i);

            // If components are different types and one is null (array selection) and the other is string (object selection)
            if (comp1 == null && comp2 instanceof String) {
                return true;
            }
            if (comp2 == null && comp1 instanceof String) {
                return true;
            }

            // If components are different types and one is integer (specific array index) and the other is null (all array elements)
            if (comp1 == null && comp2 instanceof Integer) {
                return true;
            }
            if (comp2 == null && comp1 instanceof Integer) {
                return true;
            }

            // If components are different, no conflict at this level
            if (!comp1.equals(comp2)) {
                return false;
            }
        }

        return false;
    }

    /**
     * Processes a claims path pointer against a JSON credential (for JSON-based credentials).
     *
     * @param path       the claims path pointer
     * @param credential the JSON credential to process against
     * @return the selected JSON elements, or null if processing fails
     */
    public static List<JsonNode> processJsonPath(List<Object> path, JsonNode credential) {
        if (!isValidPath(path) || credential == null) {
            return null;
        }

        try {
            List<JsonNode> selected = new ArrayList<>();
            selected.add(credential);

            for (Object component : path) {
                List<JsonNode> nextSelected = new ArrayList<>();

                for (JsonNode node : selected) {
                    if (component instanceof String) {
                        // Select object key
                        JsonNode child = node.get((String) component);
                        if (child != null) {
                            nextSelected.add(child);
                        }
                    } else if (component == null) {
                        // Select all array elements
                        if (node.isArray()) {
                            for (JsonNode child : node) {
                                nextSelected.add(child);
                            }
                        }
                    } else if (component instanceof Integer) {
                        // Select specific array index
                        if (node.isArray()) {
                            int index = (Integer) component;
                            if (index >= 0 && index < node.size()) {
                                nextSelected.add(node.get(index));
                            }
                        }
                    }
                }

                if (nextSelected.isEmpty()) {
                    return null; // No elements selected, abort processing
                }

                selected = nextSelected;
            }

            return selected;
        } catch (Exception e) {
            logger.warnf(e, "Error processing claims path pointer: %s", path);
            return null;
        }
    }
}
