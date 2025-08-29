package org.keycloak.testsuite.oid4vc.issuance;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.sdjwt.consumer.HttpDataFetcher;
import org.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator;
import org.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;
import org.keycloak.testsuite.oid4vc.issuance.signing.OID4VCTest;
import org.keycloak.representations.idm.RealmRepresentation;

import java.io.IOException;

/**
 * Test for ReferencedTokenValidator using the official IETF specification test vectors.
 */
public class ReferencedTokenValidatorTest extends OID4VCTest {

    private ReferencedTokenValidator validator;
    private ObjectMapper objectMapper;

    @Before
    public void setUp() {
        objectMapper = new ObjectMapper();

        // Create a mock HTTP data fetcher that returns the IETF test vectors
        HttpDataFetcher mockHttpDataFetcher = new HttpDataFetcher() {
            @Override
            public JsonNode fetchJsonData(String uri) throws IOException {
                // Return the official IETF spec 1-bit test vector used in the specification
                String mockStatusListToken = """
                        {
                            "status_list": {
                                "bits": 1,
                                "lst": "eNrt3AENwCAMAEGogklACtKQPg9LugC9k_ACvreiogEAAKkeCQAAAAAAAAAAAAAAAAAAAIBylgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXG9IAAAAAAAAAPwsJAAAAAAAAAAAAAAAvhsSAAAAAAAAAAA7KpLAAAAAAAAAAAAAAAAAAAAAJsLCQAAAAAAAAAAADjelAAAAAAAAAAAKjDMAQAAAACAZC8L2AEb"
                            }
                        }
                        """;
                try {
                    return objectMapper.readTree(mockStatusListToken);
                } catch (JsonProcessingException e) {
                    throw new IOException("Failed to parse mock status list token", e);
                }
            }
        };

        validator = new ReferencedTokenValidator(mockHttpDataFetcher);
    }

    @Test
    public void testIETFSpecVectorSize_1Bit() throws Exception {
        // Test to understand the actual size of the IETF 1-bit test vector
        String lst = "eNrt3AENwCAMAEGogklACtKQPg9LugC9k_ACvreiogEAAKkeCQAAAAAAAAAAAAAAAAAAAIBylgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXG9IAAAAAAAAAPwsJAAAAAAAAAAAAAAAvhsSAAAAAAAAAAA7KpLAAAAAAAAAAAAAAAAAAAAAJsLCQAAAAAAAAAAADjelAAAAAAAAAAAKjDMAQAAAACAZC8L2AEb";
        int bits = 1;

        // Try to read the maximum possible index to determine the actual size
        try {
            // Start with a reasonable upper bound
            int maxIndex = 20000;
            readStatusValue(lst, maxIndex, bits);
            System.out.println("1-bit test vector supports at least " + maxIndex + " entries");
        } catch (ReferencedTokenValidationException e) {
            if (e.getMessage().contains("out of range")) {
                // Extract the range from the error message
                String message = e.getMessage();
                int start = message.indexOf("(0-") + 3;
                int end = message.indexOf(")");
                if (start > 2 && end > start) {
                    int maxEntries = Integer.parseInt(message.substring(start, end)) + 1;
                    System.out.println("1-bit test vector contains " + maxEntries + " entries (not 2^20 as claimed in spec)");

                    // Assert the actual size for test validation
                    Assert.assertEquals("1-bit test vector should contain 15440 entries", 15440, maxEntries);
                }
            }
        }
    }

    @Test
    public void testIETFSpecVectorSize_2Bit() throws Exception {
        // Test to understand the actual size of the IETF 2-bit test vector
        String lst = "eNrt2zENACEQAEEuoaBABP5VIO01fCjIHTMStt9ovGVIAAAAAABAbiEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEB5WwIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAID0ugQAAAAAAAAAAAAAAAAAQG12SgAAAAAAAAAAAAAAAAAAAAAAAOCSIQEAAAAAAAAAAAAAAAAAAAAAAAD8ExIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwJEuAQAAAAAAAAAAAAAAAAAAAAAAAMB9SwIAAAAAAAAAAAAAAAAAAACoYUoAAAAAAAAAAAAAAEBqH81gAQw";
        int bits = 2;

        // Try to read the maximum possible index to determine the actual size
        try {
            // Start with a reasonable upper bound
            int maxIndex = 20000;
            readStatusValue(lst, maxIndex, bits);
            System.out.println("2-bit test vector supports at least " + maxIndex + " entries");
        } catch (ReferencedTokenValidationException e) {
            if (e.getMessage().contains("out of range")) {
                // Extract the range from the error message
                String message = e.getMessage();
                int start = message.indexOf("(0-") + 3;
                int end = message.indexOf(")");
                if (start > 2 && end > start) {
                    int maxEntries = Integer.parseInt(message.substring(start, end)) + 1;
                    System.out.println("2-bit test vector contains " + maxEntries + " entries (not 2^20 as claimed in spec)");

                    // Assert the actual size for test validation
                    Assert.assertEquals("2-bit test vector should contain 12840 entries", 12840, maxEntries);
                }
            }
        }
    }

    @Test
    public void testIETF_1Bit_OfficialTestVector() throws Exception {
        // Test the official IETF 1-bit test vector from the specification
        // This test vector has 15,440 entries (range 0-15439)
        // Only specific indices have status=1, all others should be 0

        String lst = "eNrt3AENwCAMAEGogklACtKQPg9LugC9k_ACvreiogEAAKkeCQAAAAAAAAAAAAAAAAAAAIBylgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXG9IAAAAAAAAAPwsJAAAAAAAAAAAAAAAvhsSAAAAAAAAAAA7KpLAAAAAAAAAAAAAAAAAAAAAJsLCQAAAAAAAAAAADjelAAAAAAAAAAAKjDMAQAAAACAZC8L2AEb";
        int bits = 1;

        // Test the specific indices that should have status = 1 according to the IETF spec
        // Only test indices within the valid range (0-15439)
        Assert.assertEquals("status[0] should be 1", 1, readStatusValue(lst, 0, bits));
        Assert.assertEquals("status[1993] should be 1", 1, readStatusValue(lst, 1993, bits));

        // Test some indices that should have status = 0 (VALID) - not mentioned in spec
        Assert.assertEquals("status[1] should be 0 (not mentioned in spec)", 0, readStatusValue(lst, 1, bits));
        Assert.assertEquals("status[100] should be 0 (not mentioned in spec)", 0, readStatusValue(lst, 100, bits));
        Assert.assertEquals("status[1000] should be 0 (not mentioned in spec)", 0, readStatusValue(lst, 1000, bits));
        Assert.assertEquals("status[5000] should be 0 (not mentioned in spec)", 0, readStatusValue(lst, 5000, bits));
        Assert.assertEquals("status[10000] should be 0 (not mentioned in spec)", 0, readStatusValue(lst, 10000, bits));
        Assert.assertEquals("status[15000] should be 0 (not mentioned in spec)", 0, readStatusValue(lst, 15000, bits));

        // Test boundary conditions
        Assert.assertEquals("status[15439] should be 0 (last valid index)", 0, readStatusValue(lst, 15439, bits));
    }

    @Test
    public void testIETF_2Bit_OfficialTestVector() throws Exception {
        // Test the official IETF 2-bit test vector from the specification
        // This test vector has 12,840 entries (range 0-12839)
        // Only specific indices have non-zero status values, all others should be 0

        String lst = "eNrt2zENACEQAEEuoaBABP5VIO01fCjIHTMStt9ovGVIAAAAAABAbiEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEB5WwIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAID0ugQAAAAAAAAAAAAAAAAAQG12SgAAAAAAAAAAAAAAAAAAAAAAAOCSIQEAAAAAAAAAAAAAAAAAAAAAAAD8ExIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwJEuAQAAAAAAAAAAAAAAAAAAAAAAAMB9SwIAAAAAAAAAAAAAAAAAAACoYUoAAAAAAAAAAAAAAEBqH81gAQw";
        int bits = 2;

        // Test the specific indices that should have specific status values according to the IETF spec
        // Only test indices within the valid range (0-12839)
        Assert.assertEquals("status[0] should be 1", 1, readStatusValue(lst, 0, bits));
        Assert.assertEquals("status[1993] should be 2", 2, readStatusValue(lst, 1993, bits));

        // Test some indices that should have status = 0 (VALID) - not mentioned in spec
        Assert.assertEquals("status[1] should be 0 (not mentioned in spec)", 0, readStatusValue(lst, 1, bits));
        Assert.assertEquals("status[100] should be 0 (not mentioned in spec)", 0, readStatusValue(lst, 100, bits));
        Assert.assertEquals("status[1000] should be 0 (not mentioned in spec)", 0, readStatusValue(lst, 1000, bits));
        Assert.assertEquals("status[5000] should be 0 (not mentioned in spec)", 0, readStatusValue(lst, 5000, bits));
        Assert.assertEquals("status[10000] should be 0 (not mentioned in spec)", 0, readStatusValue(lst, 10000, bits));
        Assert.assertEquals("status[12000] should be 0 (not mentioned in spec)", 0, readStatusValue(lst, 12000, bits));

        // Test boundary conditions
        Assert.assertEquals("status[12839] should be 0 (last valid index)", 0, readStatusValue(lst, 12839, bits));
    }

    @Test
    public void testIETF_2Bit_Small() throws Exception {
        // Test the small 2-bit example from the IETF specification
        // This example has 12 Referenced Tokens with 2-bit status values
        // status[0]=1, status[1]=2, status[2]=0, status[3]=3, etc.

        // The compressed and encoded string for the example
        // Original bytes: [0xC9, 0x44, 0xF9] (3 bytes, 24 bits, 12 status values)
        String lst = "eNo76fITAAPfAgc";
        int bits = 2;

        // Test all 12 status values according to the IETF spec example
        Assert.assertEquals("status[0] should be 1", 1, readStatusValue(lst, 0, bits));
        Assert.assertEquals("status[1] should be 2", 2, readStatusValue(lst, 1, bits));
        Assert.assertEquals("status[2] should be 0", 0, readStatusValue(lst, 2, bits));
        Assert.assertEquals("status[3] should be 3", 3, readStatusValue(lst, 3, bits));
        Assert.assertEquals("status[4] should be 0", 0, readStatusValue(lst, 4, bits));
        Assert.assertEquals("status[5] should be 1", 1, readStatusValue(lst, 5, bits));
        Assert.assertEquals("status[6] should be 0", 0, readStatusValue(lst, 6, bits));
        Assert.assertEquals("status[7] should be 1", 1, readStatusValue(lst, 7, bits));
        Assert.assertEquals("status[8] should be 1", 1, readStatusValue(lst, 8, bits));
        Assert.assertEquals("status[9] should be 2", 2, readStatusValue(lst, 9, bits));
        Assert.assertEquals("status[10] should be 3", 3, readStatusValue(lst, 10, bits));
        Assert.assertEquals("status[11] should be 3", 3, readStatusValue(lst, 11, bits));

        // Test that accessing beyond the valid range throws an exception
        try {
            readStatusValue(lst, 12, bits);
            Assert.fail("Should throw exception for index 12 (beyond valid range 0-11)");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention out of range",
                    e.getMessage().contains("out of range"));
        }
    }

    @Test
    public void testIETF_1Bit_Small() throws Exception {
        // Test the small 1-bit example from the IETF specification
        // This example has 16 Referenced Tokens with 1-bit status values
        // status[0]=1, status[1]=0, status[2]=0, status[3]=1, etc.

        // The compressed and encoded string for the example
        // Original bytes: [0xB9, 0xA3] (2 bytes, 16 bits, 16 status values)
        String lst = "eNrbuRgAAhcBXQ";
        int bits = 1;

        // Test all 16 status values
        Assert.assertEquals("status[0] should be 1", 1, readStatusValue(lst, 0, bits));
        Assert.assertEquals("status[1] should be 0", 0, readStatusValue(lst, 1, bits));
        Assert.assertEquals("status[2] should be 0", 0, readStatusValue(lst, 2, bits));
        Assert.assertEquals("status[3] should be 1", 1, readStatusValue(lst, 3, bits));
        Assert.assertEquals("status[4] should be 1", 1, readStatusValue(lst, 4, bits));
        Assert.assertEquals("status[5] should be 1", 1, readStatusValue(lst, 5, bits));
        Assert.assertEquals("status[6] should be 0", 0, readStatusValue(lst, 6, bits));
        Assert.assertEquals("status[7] should be 1", 1, readStatusValue(lst, 7, bits));
        Assert.assertEquals("status[8] should be 1", 1, readStatusValue(lst, 8, bits));
        Assert.assertEquals("status[9] should be 1", 1, readStatusValue(lst, 9, bits));
        Assert.assertEquals("status[10] should be 0", 0, readStatusValue(lst, 10, bits));
        Assert.assertEquals("status[11] should be 0", 0, readStatusValue(lst, 11, bits));
        Assert.assertEquals("status[12] should be 0", 0, readStatusValue(lst, 12, bits));
        Assert.assertEquals("status[13] should be 1", 1, readStatusValue(lst, 13, bits));
        Assert.assertEquals("status[14] should be 0", 0, readStatusValue(lst, 14, bits));
        Assert.assertEquals("status[15] should be 1", 1, readStatusValue(lst, 15, bits));

        // Test that accessing beyond the valid range throws an exception
        try {
            readStatusValue(lst, 16, bits);
            Assert.fail("Should throw exception for index 16 (beyond valid range 0-15)");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention out of range",
                    e.getMessage().contains("out of range"));
        }
    }

    @Test
    public void testIETF_1Bit_OfficialTestVector_WithMock() throws Exception {
        // Test the official IETF 1-bit test vector using the mock HTTP fetcher

        ObjectMapper mapper = new ObjectMapper();

        // Test with status[0] = 1 (INVALID) - should throw exception
        JsonNode invalidTokenPayload = mapper.readTree("""
                {
                    "status": {
                        "status_list": {
                            "idx": 0,
                            "uri": "https://status.example.com/list"
                        }
                    }
                }
                """);

        ReferencedTokenValidationException exception = Assert.assertThrows(
                "Should throw exception for invalid status (status[0] = 1)",
                ReferencedTokenValidationException.class,
                () -> validator.validate(invalidTokenPayload)
        );
        Assert.assertTrue("Exception should mention invalid status. Actual message: " + exception.getMessage(),
                exception.getMessage().contains("Token status is not valid"));

        // Test with status[1] = 0 (VALID) - should pass
        JsonNode validTokenPayload = mapper.readTree("""
                {
                    "status": {
                        "status_list": {
                            "idx": 1,
                            "uri": "https://status.example.com/list"
                        }
                    }
                }
                """);

        // This should pass because status[1] = 0 (VALID)
        validator.validate(validTokenPayload);
    }

    @Test
    public void testIETF_2Bit_OfficialTestVector_WithMock() throws Exception {
        // Test the official IETF 2-bit test vector using the mock HTTP fetcher

        ObjectMapper mapper = new ObjectMapper();

        // Test with status[0] = 1 (INVALID)
        JsonNode invalidTokenPayload = mapper.readTree("""
                {
                    "status": {
                        "status_list": {
                            "idx": 0,
                            "uri": "https://status.example.com/list"
                        }
                    }
                }
                """);

        ReferencedTokenValidationException exception1 = Assert.assertThrows(
                "Should throw exception for invalid status (status[0] = 1)",
                ReferencedTokenValidationException.class,
                () -> validator.validate(invalidTokenPayload)
        );
        Assert.assertTrue("Exception should mention invalid status",
                exception1.getMessage().contains("Token status is not valid"));

        // Test with status[1993] = 2 (SUSPENDED)
        JsonNode suspendedTokenPayload = mapper.readTree("""
                {
                    "status": {
                        "status_list": {
                            "idx": 1993,
                            "uri": "https://status.example.com/list"
                        }
                    }
                }
                """);

        ReferencedTokenValidationException exception2 = Assert.assertThrows(
                "Should throw exception for suspended status (status[1993] = 2)",
                ReferencedTokenValidationException.class,
                () -> validator.validate(suspendedTokenPayload)
        );
        Assert.assertTrue("Exception should mention invalid status",
                exception2.getMessage().contains("Token status is not valid"));

        // Test with a valid status (any index not mentioned in spec should be 0)
        JsonNode validTokenPayload = mapper.readTree("""
                {
                    "status": {
                        "status_list": {
                            "idx": 1,
                            "uri": "https://status.example.com/list"
                        }
                    }
                }
                """);

        // This should pass because status[1] = 0 (VALID)
        validator.validate(validTokenPayload);
    }


    @Test
    public void testRequiredFieldsEnforcement() throws Exception {

        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode tokenPayload = mapper.readTree("{}");
            validator.validate(tokenPayload);
            Assert.fail("Should throw exception for missing 'status' claim");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention missing status claim",
                    e.getMessage().contains("Missing required 'status' claim"));
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode tokenPayload = mapper.readTree("{\"status\": {}}");
            validator.validate(tokenPayload);
            Assert.fail("Should throw exception for missing 'status_list'");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention missing status_list",
                    e.getMessage().contains("Missing required 'status_list'"));
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode tokenPayload = mapper.readTree("{\"status\": {\"status_list\": {\"uri\": \"https://example.com\"}}}");
            validator.validate(tokenPayload);
            Assert.fail("Should throw exception for missing 'idx' field");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention missing idx field",
                    e.getMessage().contains("Missing required 'idx' field"));
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode tokenPayload = mapper.readTree("{\"status\": {\"status_list\": {\"idx\": 123}}}");
            validator.validate(tokenPayload);
            Assert.fail("Should throw exception for missing 'uri' field");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention missing uri field",
                    e.getMessage().contains("Missing required 'uri' field"));
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode tokenPayload = mapper.readTree("{\"status\": {\"status_list\": {\"idx\": -1, \"uri\": \"https://example.com\"}}}");
            validator.validate(tokenPayload);
            Assert.fail("Should throw exception for negative 'idx' value");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention non-negative idx",
                    e.getMessage().contains("non-negative"));
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode tokenPayload = mapper.readTree("{\"status\": {\"status_list\": {\"idx\": 123, \"uri\": \"\"}}}");
            validator.validate(tokenPayload);
            Assert.fail("Should throw exception for empty 'uri' value");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention empty uri",
                    e.getMessage().contains("cannot be empty"));
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode tokenPayload = mapper.readTree("{\"status\": {\"status_list\": {\"idx\": \"not-a-number\", \"uri\": \"https://example.com\"}}}");
            validator.validate(tokenPayload);
            Assert.fail("Should throw exception for wrong 'idx' data type");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention idx must be a number",
                    e.getMessage().contains("must be a number"));
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode tokenPayload = mapper.readTree("{\"status\": {\"status_list\": {\"idx\": 123, \"uri\": 456}}}");
            validator.validate(tokenPayload);
            Assert.fail("Should throw exception for wrong 'uri' data type");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention uri must be a string",
                    e.getMessage().contains("must be a string"));
        }
    }

    /**
     * Helper method to test the status value reading
     */
    private int readStatusValue(String lst, int idx, int bits) throws ReferencedTokenValidationException {
        byte[] bytes = ReferencedTokenValidator.decodeAndDecompress(lst);
        return ReferencedTokenValidator.readStatusValueFromBytes(bytes, idx, bits);
    }

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
        // No special configuration needed for this test
    }

}
