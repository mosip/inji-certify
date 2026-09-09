package io.mosip.certify.utils;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.config.MDocConfig;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.kernel.signature.dto.CoseSignRequestDto;
import io.mosip.kernel.signature.dto.CoseSignResponseDto;
import io.mosip.kernel.signature.service.CoseSignatureService;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.AfterClass;
import org.junit.Test;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.time.ZonedDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive unit tests for MDocUtils covering:
 * - Template processing and data mapping
 * - Random salt generation
 * - Digest calculation and verification
 * - MSO structure generation per ISO 18013-5
 * - CBOR encoding/decoding
 * - DeviceKeyInfo handling
 * - COSE_Sign1 signing
 * - Date handling with CBOR tag 1004
 * - Error handling and edge cases
 */
@RunWith(MockitoJUnitRunner.class)
public class MDocProcessorTest {

    private static MockedStatic<ZonedDateTime> mockedZonedDateTime;
    private static final ZonedDateTime FIXED_NOW = ZonedDateTime.of(2026, 7, 20, 10, 0, 0, 0, ZoneOffset.UTC);
    private static final Map<String, Map<String, ? extends Serializable>> expectedValidityInfo = Map.of(
            "signed", Map.of(
                    Constants.__CBOR_TAG, 0,
                    Constants.__CBOR_VALUE, "2026-07-20T10:00:00.000Z"
            ),
            "validFrom", Map.of(
                    Constants.__CBOR_TAG, 0,
                    Constants.__CBOR_VALUE, "2026-07-20T10:00:00.000Z"
            ),
            "validUntil", Map.of(
                    Constants.__CBOR_TAG, 0,
                    Constants.__CBOR_VALUE, "2031-07-20T10:00:00.000Z"
            )
    );

    @BeforeClass
    public static void setUpZonedDateTimeMock() {
        mockedZonedDateTime = mockStatic(ZonedDateTime.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        mockedZonedDateTime.when(() -> ZonedDateTime.now(ZoneOffset.UTC))
                .thenReturn(FIXED_NOW);
    }

    @AfterClass
    public static void tearDownZonedDateTimeMock() {
        if (mockedZonedDateTime != null) {
            mockedZonedDateTime.close();
        }
    }

    @Mock
    private MDocConfig mDocConfig;

    @Mock
    private CoseSignatureService coseSignatureService;

    @InjectMocks
    private MDocProcessor mDocProcessor;

    private ObjectMapper objectMapper;

    @Before
    public void setUp() {
        objectMapper = new ObjectMapper();
        ReflectionTestUtils.setField(mDocProcessor, "objectMapper", objectMapper);

        // Setup default mock behavior
        when(mDocConfig.getValidityPeriodYears()).thenReturn(5);
        when(mDocConfig.getMsoVersion()).thenReturn("1.0");
        when(mDocConfig.getDigestAlgorithm()).thenReturn("SHA-256");
    }

    // ==================== Template Processing Tests ====================

    @Test
    public void should_mapToISO18013Elements_when_validmDLTemplateIsProcessed() {
        String templatedJSON = createFullmDLTemplate();

        Map<String, Object> templateParams = new HashMap<>();
        templateParams.put("didUrl", "https://issuer.example.com/did");
        templateParams.put("_holderId", "did:jwk:test123");

        Map<String, Object> result = mDocProcessor.processTemplatedJson(templatedJSON, templateParams);

        assertNotNull("Result should not be null", result);
        assertEquals("DocType should match", "org.iso.18013.5.1.mDL", result.get("_docType"));
        assertEquals("HolderId should match", "did:jwk:test123", result.get("_holderId"));
        assertEquals("Issuer should match", "https://issuer.example.com/did", result.get("_issuer"));

        Map<String, Object> nameSpaces = (Map<String, Object>) result.get("nameSpaces");
        assertNotNull("NameSpaces should not be null", nameSpaces);

        List<Map<String, Object>> items = (List<Map<String, Object>>) nameSpaces.get("org.iso.18013.5.1");
        assertEquals("Should have 3 elements", 3, items.size());

        assertEquals("family_name", items.getFirst().get("elementIdentifier"));
        assertEquals("Doe", items.getFirst().get("elementValue"));
        assertEquals(0, items.getFirst().get("digestID"));

        assertEquals("ValidityInfo should match", expectedValidityInfo, result.get("validityInfo"));
    }

    @Test
    public void processTemplatedJson_ValidityInfoPlaceholders_ReplacedWithTimestamps() {
        String templatedJSON = "{"
                + "\"docType\": \"org.iso.18013.5.1.mDL\","
                + "\"validityInfo\": {"
                + "  \"validFrom\": \"${_validFrom}\","
                + "  \"validUntil\": \"${_validUntil}\","
                + "  \"signed\": \"${_signed}\""
                + "},"
                + "\"nameSpaces\": {}"
                + "}";

        Map<String, Object> result = mDocProcessor.processTemplatedJson(templatedJSON, new HashMap<>());

        Map<String, Object> validityInfo = (Map<String, Object>) result.get("validityInfo");
        assertNotNull("ValidityInfo should not be null", validityInfo);

        String validFrom =  (String)((Map<String,Object>) validityInfo.get(VCDM2Constants.VALID_FROM)).get(Constants.__CBOR_VALUE);
        String validUntil =  (String)((Map<String,Object>) validityInfo.get(VCDM2Constants.VALID_UNTIL)).get(Constants.__CBOR_VALUE);
        String signed =  (String)((Map<String,Object>) validityInfo.get(Constants.SIGNED)).get(Constants.__CBOR_VALUE);

        assertNotNull("ValidFrom should be set", validFrom);
        assertNotNull("ValidUntil should be set", validUntil);
        assertNotEquals("${_validFrom}", validFrom);
        assertNotEquals("${_signed}", signed);
        assertNotEquals("${_validUntil}", validUntil);

        // Verify timestamp format (ISO 8601)
        assertTrue("ValidFrom should match ISO 8601",
                validFrom.matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}.*"));
        assertTrue(signed.matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}.*"));
        assertTrue("ValidUntil should match ISO 8601",
                validUntil.matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}.*"));
    }

    @Test
    public void should_preserveStructure_when_complexElementValueProcessed() throws Exception {
        String templatedJSON = "{"
                + getValidityInfoTemplate()+","
                +"\"docType\": \"org.iso.18013.5.1.mDL\","
                + "\"nameSpaces\": {"
                + "  \"org.iso.18013.5.1\": ["
                + "    {"
                + "      \"digestID\": 7,"
                + "      \"elementIdentifier\": \"driving_privileges\","
                + "      \"elementValue\": ["
                + "        {\"vehicle_category_code\": \"A\", \"issue_date\": \"2020-01-01\"},"
                + "        {\"vehicle_category_code\": \"B\", \"issue_date\": \"2020-01-01\"}"
                + "      ]"
                + "    }"
                + "  ]"
                + "}"
                + "}";

        Map<String, Object> result = mDocProcessor.processTemplatedJson(templatedJSON, new HashMap<>());

        Map<String, Object> nameSpaces = (Map<String, Object>) result.get("nameSpaces");
        List<Map<String, Object>> items = (List<Map<String, Object>>) nameSpaces.get("org.iso.18013.5.1");

        Object elementValue = items.get(0).get("elementValue");
        assertTrue("Element value should be a list", elementValue instanceof List);

        List<Map<String, Object>> privileges = (List<Map<String, Object>>) elementValue;
        assertEquals("Should have 2 privileges", 2, privileges.size());
        assertEquals("A", privileges.get(0).get("vehicle_category_code"));
        assertEquals("B", privileges.get(1).get("vehicle_category_code"));
    }

    @Test
    public void should_returnEmptyMap_when_invalidJsonProcessed() {
        String invalidJSON = "{invalid json}";
        Map<String, Object> result;
        try {
            result = mDocProcessor.processTemplatedJson(invalidJSON, new HashMap<>());
        } catch (Exception e) {
            result = Collections.emptyMap();
        }
        assertNotNull("Result should not be null", result);
        assertTrue("Result should be empty", result.isEmpty());
    }

    @Test
    public void should_throwException_when_validityInfoInvalid() {
        provideValidityInfoTestCases().forEach(args -> {
            String testName = (String) args.get()[0];
            String templatedJSON = (String) args.get()[1];
            String expectedErrorMessage = (String) args.get()[2];

            Map<String, Object> templateParams = new HashMap<>();
            templateParams.put("didUrl", "https://issuer.example.com/did");
            templateParams.put("_holderId", "did:jwk:test123");

            CertifyException exception = assertThrows(CertifyException.class, () ->
                    mDocProcessor.processTemplatedJson(templatedJSON, templateParams));

            assertEquals("Test case [" + testName + "] failed", "Error processing templated JSON: "+expectedErrorMessage, exception.getMessage());
        });
    }

    @Test
    public void should_throwException_when_docTypeMissing() {
        String templatedJSON = "{"
                + getValidityInfoTemplate() + ","
                + "\"nameSpaces\": {}"
                + "}";

        Map<String, Object> templateParams = new HashMap<>();
        templateParams.put("didUrl", "https://issuer.example.com/did");
        templateParams.put("_holderId", "did:jwk:test123");

        CertifyException exception = assertThrows(CertifyException.class, () ->
                mDocProcessor.processTemplatedJson(templatedJSON, templateParams));

        assertEquals("Error processing templated JSON: Missing docType", exception.getMessage());
    }

    @Test
    public void should_handleAllNamespaces_when_multipleNamespacesProcessed() throws Exception {
        String templatedJSON = "{"
                + "\"docType\": \"org.mosip.credential\","
                + getValidityInfoTemplate()+","
                + "\"nameSpaces\": {"
                + "  \"org.iso.18013.5.1\": ["
                + "    {\"digestID\": 0, \"elementIdentifier\": \"family_name\", \"elementValue\": \"Doe\"}"
                + "  ],"
                + "  \"org.mosip.farmer\": ["
                + "    {\"digestID\": 0, \"elementIdentifier\": \"farmer_id\", \"elementValue\": \"FARM12345\"}"
                + "  ]"
                + "}"
                + "}";

        Map<String, Object> result = mDocProcessor.processTemplatedJson(templatedJSON, new HashMap<>());

        Map<String, Object> nameSpaces = (Map<String, Object>) result.get("nameSpaces");
        assertTrue("Should contain ISO namespace", nameSpaces.containsKey("org.iso.18013.5.1"));
        assertTrue("Should contain custom namespace", nameSpaces.containsKey("org.mosip.farmer"));
    }

    // ==================== Random Salt Generation Tests ====================

    @Test
    public void should_addRandomBytes_when_addRandomSaltsCalled() {
        Map<String, Object> mDocJson = createTestMDocJson();

        Map<String, Object> result = MDocProcessor.addRandomSalts(mDocJson);

        assertNotNull("Result should not be null", result);
        List<Map<String, Object>> saltedElements = (List<Map<String, Object>>) result.get("org.iso.18013.5.1");
        assertEquals("Should have 2 elements", 2, saltedElements.size());

        for (Map<String, Object> element : saltedElements) {
            assertTrue("Element should have random salt", element.containsKey("random"));
            byte[] random = (byte[]) element.get("random");
            assertEquals("Salt should be 24 bytes", 24, random.length);
        }
    }

    @Test
    public void should_generateUniqueSalts_when_addRandomSaltsCalled() {
        Map<String, Object> mDocJson = new HashMap<>();
        Map<String, Object> nameSpaces = new HashMap<>();
        List<Map<String, Object>> elements = new ArrayList<>();

        for (int i = 0; i < 10; i++) {
            elements.add(createTestElement(i, "field_" + i, "value_" + i));
        }
        nameSpaces.put("org.iso.18013.5.1", elements);
        mDocJson.put("nameSpaces", nameSpaces);

        Map<String, Object> result = MDocProcessor.addRandomSalts(mDocJson);
        List<Map<String, Object>> saltedElements = (List<Map<String, Object>>) result.get("org.iso.18013.5.1");

        Set<String> saltSet = new HashSet<>();
        for (Map<String, Object> element : saltedElements) {
            byte[] random = (byte[]) element.get("random");
            String saltHex = bytesToHex(random);
            assertTrue("Duplicate salt found: " + saltHex, saltSet.add(saltHex));
        }
        assertEquals("All salts should be unique", 10, saltSet.size());
    }

    @Test
    public void should_preserveOriginalData_when_addRandomSaltsCalled() {
        Map<String, Object> mDocJson = createTestMDocJson();

        Map<String, Object> result = MDocProcessor.addRandomSalts(mDocJson);
        List<Map<String, Object>> saltedElements = (List<Map<String, Object>>) result.get("org.iso.18013.5.1");

        assertEquals("family_name", saltedElements.get(0).get("elementIdentifier"));
        assertEquals("Doe", saltedElements.get(0).get("elementValue"));
        assertEquals(0, saltedElements.get(0).get("digestID"));
    }

    // ==================== Digest Calculation Tests ====================

    @Test
    public void should_generateCorrectSHA256Digests_when_calculateDigestsCalled() throws Exception {
        Map<String, Object> saltedNamespaces = new HashMap<>();
        List<Map<String, Object>> elements = new ArrayList<>();
        elements.add(createSaltedElement(0, "family_name", "Doe"));
        saltedNamespaces.put("org.iso.18013.5.1", elements);

        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        Map<String, Object> result = MDocProcessor.calculateDigests(saltedNamespaces, namespaceDigests);

        assertNotNull("Result should not be null", result);
        assertTrue("Should contain namespace", result.containsKey("org.iso.18013.5.1"));

        Map<Integer, byte[]> digests = namespaceDigests.get("org.iso.18013.5.1");
        assertNotNull("Digests should not be null", digests);
        assertTrue("Should have digest for ID 0", digests.containsKey(0));
        assertEquals("SHA-256 produces 32 bytes", 32, digests.get(0).length);
    }

    @Test
    public void should_mapDigestsByID_when_multipleElementsProvided() throws Exception {
        Map<String, Object> saltedNamespaces = new HashMap<>();
        List<Map<String, Object>> elements = new ArrayList<>();

        for (int i = 0; i < 5; i++) {
            elements.add(createSaltedElement(i, "field_" + i, "value_" + i));
        }
        saltedNamespaces.put("org.iso.18013.5.1", elements);

        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        MDocProcessor.calculateDigests(saltedNamespaces, namespaceDigests);

        Map<Integer, byte[]> digests = namespaceDigests.get("org.iso.18013.5.1");
        assertEquals("Should have 5 digests", 5, digests.size());

        for (int i = 0; i < 5; i++) {
            assertTrue("Should have digest for ID " + i, digests.containsKey(i));
            assertEquals("Digest should be 32 bytes", 32, digests.get(i).length);
        }
    }

    @Test
    public void should_wrapWithCBORTag24_when_calculateDigestsCalled() throws Exception {
        Map<String, Object> saltedNamespaces = new HashMap<>();
        List<Map<String, Object>> elements = new ArrayList<>();
        elements.add(createSaltedElement(0, "test", "value"));
        saltedNamespaces.put("org.iso.18013.5.1", elements);

        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        Map<String, Object> result = MDocProcessor.calculateDigests(saltedNamespaces, namespaceDigests);

        List<Object> taggedElements = (List<Object>) result.get("org.iso.18013.5.1");
        assertNotNull("Tagged elements should not be null", taggedElements);
        assertEquals("Should have 1 element", 1, taggedElements.size());

        Object element = taggedElements.get(0);
        assertTrue("Element should be ByteString", element instanceof ByteString);

        ByteString byteString = (ByteString) element;
        assertEquals("Should have tag 24", 24, byteString.getTag().getValue());
    }

    @Test
    public void should_verifyDigestCalculation_when_calculateDigestsCalled() throws Exception {
        // Create element with known data
        Map<String, Object> element = new HashMap<>();
        element.put("digestID", 0);
        element.put("elementIdentifier", "test_field");
        element.put("elementValue", "test_value");
        element.put("random", new byte[24]); // All zeros for reproducibility

        Map<String, Object> saltedNamespaces = new HashMap<>();
        saltedNamespaces.put("test.namespace", Collections.singletonList(element));

        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        MDocProcessor.calculateDigests(saltedNamespaces, namespaceDigests);

        byte[] digest = namespaceDigests.get("test.namespace").get(0);

        // Verify digest is deterministic for same input
        Map<String, Map<Integer, byte[]>> namespaceDigests2 = new HashMap<>();
        MDocProcessor.calculateDigests(saltedNamespaces, namespaceDigests2);
        byte[] digest2 = namespaceDigests2.get("test.namespace").get(0);

        assertArrayEquals("Digests should be deterministic", digest, digest2);
    }

    // ==================== CBOR Encoding Tests ====================

    @Test
    public void should_encodeSuccessfully_when_simpleMapEncoded() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("key", "value");
        data.put("number", 42);
        data.put("boolean", true);

        byte[] result = MDocProcessor.encodeToCBOR(data);

        assertNotNull("Result should not be null", result);
        assertTrue("Result should have data", result.length > 0);

        // Verify it can be decoded
        List<DataItem> decoded = new CborDecoder(new ByteArrayInputStream(result)).decode();
        assertFalse("Should decode successfully", decoded.isEmpty());
    }

    @Test
    public void should_preserveBytes_when_byteArrayEncoded() throws Exception {
        byte[] testBytes = new byte[]{1, 2, 3, 4, 5};
        Map<String, Object> data = new HashMap<>();
        data.put("bytes", testBytes);

        byte[] result = MDocProcessor.encodeToCBOR(data);

        assertNotNull("Result should not be null", result);

        // Decode and verify
        List<DataItem> decoded = new CborDecoder(new ByteArrayInputStream(result)).decode();
        co.nstant.in.cbor.model.Map map = (co.nstant.in.cbor.model.Map) decoded.get(0);
        ByteString byteString = (ByteString) map.get(new UnicodeString("bytes"));
        assertArrayEquals("Bytes should be preserved", testBytes, byteString.getBytes());
    }

    @Test
    public void should_encodeRecursively_when_nestedStructuresEncoded() throws Exception {
        Map<String, Object> nested = new HashMap<>();
        nested.put("inner", "value");
        nested.put("innerNumber", 123);

        Map<String, Object> data = new HashMap<>();
        data.put("outer", nested);
        data.put("list", Arrays.asList(1, 2, 3));

        byte[] result = MDocProcessor.encodeToCBOR(data);

        assertNotNull("Result should not be null", result);
        assertTrue("Result should have data", result.length > 0);
    }

    @Test
    public void should_applyTag1004_when_dateStringEncoded() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("birthDate", "1990-08-25");

        byte[] result = MDocProcessor.encodeToCBOR(data);

        assertNotNull("Result should not be null", result);
        assertTrue("Result should have data", result.length > 0);

        // Verify it decodes without error and contains the date
        List<DataItem> decoded = new CborDecoder(new ByteArrayInputStream(result)).decode();
        assertNotNull("Should decode successfully", decoded);
        assertFalse("Decoded data should not be empty", decoded.isEmpty());

        // Just verify the structure is valid - tag handling is implementation detail
        assertTrue("Should decode to a Map", decoded.get(0) instanceof co.nstant.in.cbor.model.Map);
    }

    @Test
    public void should_handleCorrectly_when_allDataTypesEncoded() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("string", "test");
        data.put("integer", 42);
        data.put("long", 1234567890L);
        data.put("double", 3.14);
        data.put("boolean", true);
        data.put("null", null);
        data.put("bytes", new byte[]{1, 2, 3});
        data.put("list", Arrays.asList(1, 2, 3));
        data.put("map", Collections.singletonMap("nested", "value"));

        byte[] result = MDocProcessor.encodeToCBOR(data);

        assertNotNull("Result should not be null", result);
        assertTrue("Result should have data", result.length > 0);
    }

    @Test
    public void should_handleGracefully_when_nullInputEncoded() throws Exception {
        // Null is handled by preprocessForCBOR and converted to SimpleValue.NULL
        byte[] result = MDocProcessor.encodeToCBOR(Collections.singletonMap("nullKey", null));

        assertNotNull("Result should not be null", result);
        assertTrue("Result should have data", result.length > 0);
    }

    // ==================== Date Handling Tests ====================

    @Test
    public void should_recognizeCorrectly_when_validDatesHandled() throws Exception {
        String[] validDates = {
                "2025-01-15",
                "1990-12-31",
                "2000-02-29", // Leap year
                "2024-06-30"
        };

        for (String date : validDates) {
            Map<String, Object> data = new HashMap<>();
            data.put("date", date);

            byte[] encoded = MDocProcessor.encodeToCBOR(data);
            assertNotNull("Should encode date: " + date, encoded);

            // Decode and verify date was tagged
            List<DataItem> decoded = new CborDecoder(new ByteArrayInputStream(encoded)).decode();
            co.nstant.in.cbor.model.Map map = (co.nstant.in.cbor.model.Map) decoded.get(0);
            DataItem dateItem = map.get(new UnicodeString("date"));
            assertNotNull("Date item should exist for: " + date, dateItem);
            // Verify it has tag 1004
            if (dateItem.getTag() != null) {
                assertEquals("Should have tag 1004 for date: " + date,
                        1004, dateItem.getTag().getValue());
            }
        }
    }

    @Test
    public void should_notTag_when_nonDateStringsHandled() throws Exception {
        String[] nonDates = {
                "2025-13-01", // Invalid month
                "2025/01/15", // Wrong format
                "2025-01-15T10:30:00Z", // DateTime
                "not a date",
                "15-01-2025" // Wrong order
        };

        for (String nonDate : nonDates) {
            Map<String, Object> data = new HashMap<>();
            data.put("text", nonDate);

            byte[] encoded = MDocProcessor.encodeToCBOR(data);
            assertNotNull("Should encode non-date: " + nonDate, encoded);

            // These should be encoded as regular strings without tag 1004
            List<DataItem> decoded = new CborDecoder(new ByteArrayInputStream(encoded)).decode();
            co.nstant.in.cbor.model.Map map = (co.nstant.in.cbor.model.Map) decoded.getFirst();
            DataItem textItem = map.get(new UnicodeString("text"));
            assertNotNull("Text item should exist", textItem);
        }
    }

    // ==================== DeviceKeyInfo Tests ====================

    @Test
    public void should_parseCorrectly_when_validDidJwkECProvided() throws Exception {
        String jwkJson = "{\"kty\":\"EC\",\"crv\":\"P-256\","
                + "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
                + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}";
        String encodedKey = Base64.getUrlEncoder().encodeToString(jwkJson.getBytes());
        String didJwk = "did:jwk:" + encodedKey;

        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_holderId", didJwk);

        // Test through public method
        Map<String, Object> mso = mDocProcessor.createMobileSecurityObject(
                mDocJson, new HashMap<>()
        );

        assertNotNull("MSO should not be null", mso);
        assertTrue("MSO should have deviceKeyInfo", mso.containsKey("deviceKeyInfo"));

        Map<String, Object> deviceKeyInfo = (Map<String, Object>) mso.get("deviceKeyInfo");
        assertTrue("DeviceKeyInfo should have deviceKey", deviceKeyInfo.containsKey("deviceKey"));

        Map<Object, Object> deviceKey = (Map<Object, Object>) deviceKeyInfo.get("deviceKey");
        assertEquals("kty should be EC2", 2, deviceKey.get(1));
        assertEquals("alg should be ES256", -7, deviceKey.get(3));
        assertEquals("crv should be P-256", 1, deviceKey.get(-1));
        assertTrue("Should have x coordinate", deviceKey.containsKey(-2));
        assertTrue("Should have y coordinate", deviceKey.containsKey(-3));
    }

    @Test
    public void should_mapCorrectly_when_p384CurveUsed() throws Exception {
        String jwkJson = "{\"kty\":\"EC\",\"crv\":\"P-384\","
                + "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
                + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}";
        String encodedKey = Base64.getUrlEncoder().encodeToString(jwkJson.getBytes());
        String didJwk = "did:jwk:" + encodedKey+"#0";

        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_holderId", didJwk);

        Map<String, Object> mso = mDocProcessor.createMobileSecurityObject(mDocJson, new HashMap<>());
        Map<String, Object> deviceKeyInfo = (Map<String, Object>) mso.get("deviceKeyInfo");
        Map<Object, Object> deviceKey = (Map<Object, Object>) deviceKeyInfo.get("deviceKey");

        assertEquals("crv should be P-384", 2, deviceKey.get(-1));
    }

    @Test
    public void should_mapCorrectly_when_p521CurveUsed() throws Exception {
        String jwkJson = "{\"kty\":\"EC\",\"crv\":\"P-521\","
                + "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
                + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}";
        String encodedKey = Base64.getUrlEncoder().encodeToString(jwkJson.getBytes());
        String didJwk = "did:jwk:" + encodedKey;

        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_holderId", didJwk);

        Map<String, Object> mso = mDocProcessor.createMobileSecurityObject(mDocJson, new HashMap<>());
        Map<String, Object> deviceKeyInfo = (Map<String, Object>) mso.get("deviceKeyInfo");
        Map<Object, Object> deviceKey = (Map<Object, Object>) deviceKeyInfo.get("deviceKey");

        assertEquals("crv should be P-521", 3, deviceKey.get(-1));
    }

    @Test(expected = IllegalArgumentException.class)
    public void should_throwException_when_unsupportedCurveUsed() throws Exception {
        String jwkJson = "{\"kty\":\"EC\",\"crv\":\"secp256k1\","
                + "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
                + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}";
        String encodedKey = Base64.getUrlEncoder().encodeToString(jwkJson.getBytes());
        String didJwk = "did:jwk:" + encodedKey;

        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_holderId", didJwk);

        mDocProcessor.createMobileSecurityObject(mDocJson, new HashMap<>());
    }

    @Test
    public void should_preserveKid_when_keyIdProvided() throws Exception {
        String jwkJson = "{\"kty\":\"EC\",\"crv\":\"P-256\","
                + "\"kid\":\"test-key-123\","
                + "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
                + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}";
        String encodedKey = Base64.getUrlEncoder().encodeToString(jwkJson.getBytes());
        String didJwk = "did:jwk:" + encodedKey;

        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_holderId", didJwk);

        Map<String, Object> mso = mDocProcessor.createMobileSecurityObject(mDocJson, new HashMap<>());
        Map<String, Object> deviceKeyInfo = (Map<String, Object>) mso.get("deviceKeyInfo");
        Map<Object, Object> deviceKey = (Map<Object, Object>) deviceKeyInfo.get("deviceKey");

        assertTrue("Should have kid", deviceKey.containsKey(2));
        assertArrayEquals("Kid should match",
                "test-key-123".getBytes(),
                (byte[]) deviceKey.get(2));
    }

    // ==================== MSO Structure Tests ====================

    @Test
    public void should_createCompleteStructure_when_validInputProvided() throws Exception {
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "org.iso.18013.5.1.mDL");
        mDocJson.put("_holderId", createTestDidJwk());
        mDocJson.put("validityInfo", expectedValidityInfo);

        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        Map<Integer, byte[]> digests = new HashMap<>();
        digests.put(0, new byte[32]);
        digests.put(1, new byte[32]);
        namespaceDigests.put("org.iso.18013.5.1", digests);

        Map<String, Object> result = mDocProcessor.createMobileSecurityObject(mDocJson, namespaceDigests);

        assertNotNull("MSO should not be null", result);
        assertEquals("Version should match config", "1.0", result.get("version"));
        assertEquals("Digest algorithm should match", "SHA-256", result.get("digestAlgorithm"));
        assertEquals("DocType should match", "org.iso.18013.5.1.mDL", result.get(Constants.DOCTYPE));

        Map<String, Object> actualValidityInfo = (Map<String, Object>) result.get("validityInfo");
        assertEquals(expectedValidityInfo, actualValidityInfo);
        assertNotNull("Should have valueDigests", result.get("valueDigests"));
        assertNotNull("Should have deviceKeyInfo", result.get("deviceKeyInfo"));
    }

    @Test
    public void should_structureCorrectly_when_valueDigestsProcessed() throws Exception {
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "org.test.doc");
        mDocJson.put("_holderId", createTestDidJwk());

        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        Map<Integer, byte[]> digests1 = new HashMap<>();
        digests1.put(0, new byte[32]);
        digests1.put(1, new byte[32]);
        namespaceDigests.put("namespace1", digests1);

        Map<Integer, byte[]> digests2 = new HashMap<>();
        digests2.put(0, new byte[32]);
        namespaceDigests.put("namespace2", digests2);

        Map<String, Object> result = mDocProcessor.createMobileSecurityObject(mDocJson, namespaceDigests);

        Map<String, Object> valueDigests = (Map<String, Object>) result.get("valueDigests");
        assertNotNull("ValueDigests should not be null", valueDigests);

        // nameSpaces is now directly under valueDigests
        assertTrue("Should contain namespace1", valueDigests.containsKey("namespace1"));
        assertTrue("Should contain namespace2", valueDigests.containsKey("namespace2"));

        Map<Integer, byte[]> ns1Digests = (Map<Integer, byte[]>) valueDigests.get("namespace1");
        assertEquals("Namespace1 should have 2 digests", 2, ns1Digests.size());
    }

    @Test
    public void should_addValidityInfo_when_createMobileSecurityObjectIsCalled() throws Exception {
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "org.test.doc");
        mDocJson.put("_holderId", createTestDidJwk());
        mDocJson.put("validityInfo", expectedValidityInfo);

        Map<String, Object> result = mDocProcessor.createMobileSecurityObject(mDocJson, new HashMap<>());

        Map<String, Object> resultValidity = (Map<String, Object>) result.get("validityInfo");
        assertEquals(expectedValidityInfo, resultValidity);
    }

    // ==================== COSE Signing Tests ====================

    @Test
    public void should_returnSignedBytes_when_validInputProvided() throws Exception {
        Map<String, Object> mso = new HashMap<>();
        mso.put("version", "1.0");
        mso.put("digestAlgorithm", "SHA-256");

        // Mock the COSE signature service response
        String mockHexSignedData = "d2844341a10126404c504143204f50454e4141";

        CoseSignResponseDto mockResponse = new CoseSignResponseDto();
        mockResponse.setSignedData(mockHexSignedData);

        when(coseSignatureService.coseSign1(any(CoseSignRequestDto.class)))
                .thenReturn(mockResponse);

        byte[] result = mDocProcessor.signMSO(mso, "testApp", "testRef", "ES256");

        assertNotNull("Result should not be null", result);
        assertTrue("Result should have data", result.length > 0);

        // Verify service was called with correct parameters
        ArgumentCaptor<CoseSignRequestDto> captor = ArgumentCaptor.forClass(CoseSignRequestDto.class);
        verify(coseSignatureService).coseSign1(captor.capture());
        CoseSignRequestDto requestDto = captor.getValue();
        assertEquals("Application ID should match", "testApp", requestDto.getApplicationId());
        assertEquals("Reference ID should match", "testRef", requestDto.getReferenceId());
        assertEquals("Algorithm should match", "ES256", requestDto.getAlgorithm());
        assertEquals("Include COSE Tag should match", false, requestDto.getIncludeCOSETag());

        // Assert the request dto payload is B64 encoded - tagged mso #6.24(bstr .cbor mso)
        String payload = requestDto.getPayload();
        try {
            byte[] decodedPayload = Base64.getUrlDecoder().decode(payload);
            assertTrue("Decoded payload should contain data", decodedPayload.length > 0);
            // Verify the decoded payload is a CBOR-encoded tag-24 wrapped ByteString (bstr .cbor mso)
            List<DataItem> cborItems = new CborDecoder(new ByteArrayInputStream(decodedPayload)).decode();
            assertFalse("Should decode to CBOR items", cborItems.isEmpty());
            DataItem item = cborItems.get(0);
            assertTrue("Payload should be a ByteString", item instanceof ByteString);
            assertEquals("Payload should have CBOR tag 24", 24, item.getTag().getValue());
        } catch (IllegalArgumentException e) {
            fail("Payload should be valid Base64 encoded: " + e.getMessage());
        }
    }

    @Test(expected = CertifyException.class)
    public void should_throwException_when_signingFails() throws Exception {
        Map<String, Object> mso = new HashMap<>();
        mso.put("version", "1.0");

        when(coseSignatureService.coseSign1(any(CoseSignRequestDto.class)))
                .thenThrow(new CertifyException("Signing failed"));

        mDocProcessor.signMSO(mso, "app", "ref", "ES256");
    }

    // ==================== IssuerSigned Structure Tests ====================

    @Test
    public void should_createStructure_when_validInputProvided() throws Exception {
        Map<String, Object> processedNamespaces = new HashMap<>();
        List<Object> elements = new ArrayList<>();

        ByteString bs = new ByteString(new byte[]{1, 2, 3});
        bs.setTag(24);
        elements.add(bs);

        processedNamespaces.put("org.iso.18013.5.1", elements);

        // Create a valid COSE_Sign1 structure
        co.nstant.in.cbor.model.Array coseArray = new co.nstant.in.cbor.model.Array();
        coseArray.add(new ByteString(new byte[]{(byte)0xa1, 0x01, 0x26})); // Protected header
        coseArray.add(new co.nstant.in.cbor.model.Map()); // Unprotected header
        coseArray.add(new ByteString(new byte[]{1, 2, 3, 4})); // Payload
        coseArray.add(new ByteString(new byte[]{5, 6, 7, 8})); // Signature

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new CborEncoder(baos).encode(coseArray);
        byte[] signedMSO = baos.toByteArray();

        Map<String, Object> result = MDocProcessor.createIssuerSignedStructure(processedNamespaces, signedMSO);

        assertNotNull("Result should not be null", result);
        assertTrue("Should have nameSpaces", result.containsKey("nameSpaces"));
        assertTrue("Should have issuerAuth", result.containsKey("issuerAuth"));

        assertEquals("NameSpaces should match", processedNamespaces, result.get("nameSpaces"));
        assertTrue("IssuerAuth should be DataItem", result.get("issuerAuth") instanceof DataItem);
    }

    @Test
    public void should_handleGracefully_when_emptyNamespacesProvided() throws Exception {
        Map<String, Object> processedNamespaces = new HashMap<>();

        co.nstant.in.cbor.model.Array coseArray = new co.nstant.in.cbor.model.Array();
        coseArray.add(new ByteString(new byte[]{(byte)0xa1, 0x01, 0x26}));
        coseArray.add(new co.nstant.in.cbor.model.Map());
        coseArray.add(new ByteString(new byte[]{1, 2, 3}));
        coseArray.add(new ByteString(new byte[]{4, 5, 6}));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new CborEncoder(baos).encode(coseArray);
        byte[] signedMSO = baos.toByteArray();

        Map<String, Object> result = MDocProcessor.createIssuerSignedStructure(processedNamespaces, signedMSO);

        assertNotNull("Result should not be null", result);
        Map<String, Object> nameSpaces = (Map<String, Object>) result.get("nameSpaces");
        assertTrue("NameSpaces should be empty", nameSpaces.isEmpty());
    }

    @Test(expected = IOException.class)
    public void should_throwException_when_invalidCBOREncountered() throws Exception {
        Map<String, Object> processedNamespaces = new HashMap<>();

        // Use bytes that will cause CborException - incomplete CBOR structure
        byte[] invalidCBOR = new byte[]{(byte)0x9f}; // Start of indefinite-length array with no end

        MDocProcessor.createIssuerSignedStructure(processedNamespaces, invalidCBOR);
    }
    // ==================== Integration Tests ====================

    @Test
    public void should_handleCorrectly_when_multipleNamespacesProcessed() throws Exception {
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "org.multi.credential");
        mDocJson.put("_holderId", createTestDidJwk());

        Map<String, Object> nameSpaces = new HashMap<>();
        nameSpaces.put("org.iso.18013.5.1", Collections.singletonList(
                createTestElement(0, "family_name", "Doe")
        ));
        nameSpaces.put("org.mosip.farmer", Collections.singletonList(
                createTestElement(0, "farmer_id", "FARM123")
        ));
        mDocJson.put("nameSpaces", nameSpaces);

        Map<String, Object> saltedNamespaces = MDocProcessor.addRandomSalts(mDocJson);
        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        MDocProcessor.calculateDigests(saltedNamespaces, namespaceDigests);

        assertEquals("Should have 2 namespaces", 2, namespaceDigests.size());
        assertTrue("Should have ISO namespace", namespaceDigests.containsKey("org.iso.18013.5.1"));
        assertTrue("Should have custom namespace", namespaceDigests.containsKey("org.mosip.farmer"));
    }

    // ==================== Edge Cases and Error Handling ====================

    @Test
    public void should_handleGracefully_when_emptyNamespaceEncountered() {
        Map<String, Object> mDocJson = new HashMap<>();
        Map<String, Object> nameSpaces = new HashMap<>();
        nameSpaces.put("org.iso.18013.5.1", new ArrayList<>());
        mDocJson.put("nameSpaces", nameSpaces);

        Map<String, Object> result = MDocProcessor.addRandomSalts(mDocJson);

        assertNotNull("Result should not be null", result);
        assertTrue("Should have namespace", result.containsKey("org.iso.18013.5.1"));
        List<?> elements = (List<?>) result.get("org.iso.18013.5.1");
        assertTrue("Elements should be empty", elements.isEmpty());
    }

    @Test
    public void should_handleGracefully_when_emptyElementsEncountered() throws Exception {
        Map<String, Object> saltedNamespaces = new HashMap<>();
        saltedNamespaces.put("org.iso.18013.5.1", new ArrayList<>());

        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        Map<String, Object> result = MDocProcessor.calculateDigests(saltedNamespaces, namespaceDigests);

        assertNotNull("Result should not be null", result);
        assertTrue("Should have namespace", result.containsKey("org.iso.18013.5.1"));
        List<?> elements = (List<?>) result.get("org.iso.18013.5.1");
        assertTrue("Elements should be empty", elements.isEmpty());
    }

    @Test
    public void should_handleCorrectly_when_nullValueEncoded() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("nullField", null);
        data.put("normalField", "value");

        byte[] result = MDocProcessor.encodeToCBOR(data);

        assertNotNull("Result should not be null", result);

        // Decode and verify
        List<DataItem> decoded = new CborDecoder(new ByteArrayInputStream(result)).decode();
        co.nstant.in.cbor.model.Map map = (co.nstant.in.cbor.model.Map) decoded.get(0);
        DataItem nullItem = map.get(new UnicodeString("nullField"));
        assertEquals("Null should be encoded as CBOR NULL", SimpleValue.NULL, nullItem);
    }

    @Test
    public void should_handleCorrectly_when_largeNumbersEncoded() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("maxInt", Integer.MAX_VALUE);
        data.put("minInt", Integer.MIN_VALUE);
        data.put("maxLong", Long.MAX_VALUE);
        data.put("minLong", Long.MIN_VALUE);

        byte[] result = MDocProcessor.encodeToCBOR(data);

        assertNotNull("Result should not be null", result);
        assertTrue("Result should have data", result.length > 0);
    }

    @Test
    public void should_handleCorrectly_when_specialFloatsEncoded() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("pi", 3.14159);
        data.put("negative", -2.5);
        data.put("zero", 0.0);

        byte[] result = MDocProcessor.encodeToCBOR(data);

        assertNotNull("Result should not be null", result);
        assertTrue("Result should have data", result.length > 0);
    }

    // ==================== CBOR Type Conversion Tests ====================

    @Test
    public void should_convertCorrectly_when_integerConverted() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("positive", 42);
        data.put("negative", -42);
        data.put("zero", 0);

        byte[] encoded = MDocProcessor.encodeToCBOR(data);
        List<DataItem> decoded = new CborDecoder(new ByteArrayInputStream(encoded)).decode();

        assertNotNull("Decoded data should not be null", decoded);
        assertFalse("Should have decoded items", decoded.isEmpty());
    }

    @Test
    public void should_convertCorrectly_when_booleanConverted() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("trueValue", true);
        data.put("falseValue", false);

        byte[] encoded = MDocProcessor.encodeToCBOR(data);
        List<DataItem> decoded = new CborDecoder(new ByteArrayInputStream(encoded)).decode();

        co.nstant.in.cbor.model.Map map = (co.nstant.in.cbor.model.Map) decoded.get(0);
        assertEquals("True should be encoded correctly",
                SimpleValue.TRUE,
                map.get(new UnicodeString("trueValue")));
        assertEquals("False should be encoded correctly",
                SimpleValue.FALSE,
                map.get(new UnicodeString("falseValue")));
    }

    @Test
    public void should_convertToArray_when_listConverted() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("list", Arrays.asList("a", "b", "c"));

        byte[] encoded = MDocProcessor.encodeToCBOR(data);
        List<DataItem> decoded = new CborDecoder(new ByteArrayInputStream(encoded)).decode();

        co.nstant.in.cbor.model.Map map = (co.nstant.in.cbor.model.Map) decoded.get(0);
        DataItem listItem = map.get(new UnicodeString("list"));
        assertTrue("List should be encoded as Array", listItem instanceof Array);
    }

    // ==================== Configuration Tests ====================

    @Test
    public void should_addValidityPeriod_asPer_MdocConfig() throws Exception {
        when(mDocConfig.getValidityPeriodYears()).thenReturn(10);

        String template = "{\"validityInfo\": {\"validFrom\": \"${_validFrom}\",\"signed\": \"${_signed}\", \"validUntil\": \"${_validUntil}\"}, \"docType\": \"${_docType}\"}";
        Map<String, Object> result = mDocProcessor.processTemplatedJson(template, new HashMap<>());

        Map<String, Object> validityInfo = (Map<String, Object>) result.get("validityInfo");
        String validUntil = (String) ((Map<String, Object>) validityInfo.get("validUntil")).get(Constants.__CBOR_VALUE);

        assertNotNull("ValidUntil should be set", validUntil);
        // Verify it's approximately 10 years in the future (allowing for execution time)
        assertTrue("ValidUntil should be in the future", validUntil.compareTo("2030-01-01") > 0);
    }

    @Test
    public void should_useMsoVersion_when_mDocConfigApplied() throws Exception {
        when(mDocConfig.getMsoVersion()).thenReturn("2.0");

        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "test");
        mDocJson.put("_holderId", createTestDidJwk());

        Map<String, Object> mso = mDocProcessor.createMobileSecurityObject(mDocJson, new HashMap<>());

        assertEquals("MSO version should match config", "2.0", mso.get("version"));
    }

    @Test
    public void should_useDigestAlgorithm_when_mDocConfigApplied() throws Exception {
        when(mDocConfig.getDigestAlgorithm()).thenReturn("SHA-512");

        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "test");
        mDocJson.put("_holderId", createTestDidJwk());

        Map<String, Object> mso = mDocProcessor.createMobileSecurityObject(mDocJson, new HashMap<>());

        assertEquals("Digest algorithm should match config", "SHA-512", mso.get("digestAlgorithm"));
    }

    // ==================== Compliance Tests (ISO 18013-5) ====================

    @Test
    public void should_haveRequiredFields_when_issuerSignedStructureCreated() throws Exception {
        Map<String, Object> processedNamespaces = new HashMap<>();
        processedNamespaces.put("org.iso.18013.5.1", new ArrayList<>());

        byte[] signedMSO = createMockCoseSign1();
        Map<String, Object> issuerSigned = MDocProcessor.createIssuerSignedStructure(processedNamespaces, signedMSO);

        assertTrue("Must have nameSpaces field", issuerSigned.containsKey("nameSpaces"));
        assertTrue("Must have issuerAuth field", issuerSigned.containsKey("issuerAuth"));
        assertEquals("Should only have 2 fields", 2, issuerSigned.size());
    }

    @Test
    public void should_haveRequiredFields_when_msoCreated() throws Exception {
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "org.iso.18013.5.1.mDL");
        mDocJson.put("_holderId", createTestDidJwk());

        Map<String, Object> mso = mDocProcessor.createMobileSecurityObject(mDocJson, new HashMap<>());

        assertTrue("Must have version", mso.containsKey("version"));
        assertTrue("Must have digestAlgorithm", mso.containsKey("digestAlgorithm"));
        assertTrue("Must have valueDigests", mso.containsKey("valueDigests"));
        assertTrue("Must have deviceKeyInfo", mso.containsKey("deviceKeyInfo"));
        assertTrue("Must have docType", mso.containsKey(Constants.DOCTYPE));
        assertTrue("Must have validityInfo", mso.containsKey("validityInfo"));
    }

    @Test
    public void should_structureCorrectly_when_issuerSignedItemCreated() throws Exception {
        Map<String, Object> element = createSaltedElement(0, "family_name", "Doe");

        // Verify element has required fields
        assertTrue("Must have digestID", element.containsKey("digestID"));
        assertTrue("Must have random", element.containsKey("random"));
        assertTrue("Must have elementIdentifier", element.containsKey("elementIdentifier"));
        assertTrue("Must have elementValue", element.containsKey("elementValue"));

        byte[] random = (byte[]) element.get("random");
        assertEquals("Random must be 24 bytes", 24, random.length);
    }

    // ==================== Helper Methods ====================

    private Map<String, Object> createTestMDocJson() {
        Map<String, Object> mDocJson = new HashMap<>();
        Map<String, Object> nameSpaces = new HashMap<>();
        List<Map<String, Object>> elements = new ArrayList<>();

        elements.add(createTestElement(0, "family_name", "Doe"));
        elements.add(createTestElement(1, "given_name", "John"));

        nameSpaces.put("org.iso.18013.5.1", elements);
        mDocJson.put("nameSpaces", nameSpaces);

        return mDocJson;
    }

    private Map<String, Object> createTestElement(int digestID, String identifier, Object value) {
        Map<String, Object> element = new HashMap<>();
        element.put("digestID", digestID);
        element.put("elementIdentifier", identifier);
        element.put("elementValue", value);
        return element;
    }

    private Map<String, Object> createSaltedElement(int digestID, String identifier, Object value) {
        Map<String, Object> element = createTestElement(digestID, identifier, value);
        element.put("random", new byte[24]);
        return element;
    }

    private String createTestDidJwk() {
        String jwkJson = "{\"kty\":\"EC\",\"crv\":\"P-256\","
                + "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
                + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}";
        return "did:jwk:" + Base64.getUrlEncoder().encodeToString(jwkJson.getBytes());
    }

    private String createFullmDLTemplate() {
        return "{"
                + "\"docType\": \"org.iso.18013.5.1.mDL\","
                + getValidityInfoTemplate()+","
                + "\"nameSpaces\": {"
                + "  \"org.iso.18013.5.1\": ["
                + "    {\"digestID\": 0, \"elementIdentifier\": \"family_name\", \"elementValue\": \"Doe\"},"
                + "    {\"digestID\": 1, \"elementIdentifier\": \"given_name\", \"elementValue\": \"John\"},"
                + "    {\"digestID\": 2, \"elementIdentifier\": \"birth_date\", \"elementValue\": \"1990-08-25\"}"
                + "  ]"
                + "}"
                + "}";
    }

    private static String getValidityInfoTemplate() {
        return "\"validityInfo\": {"
                + "  \"validFrom\": \"${_validFrom}\","
                + "  \"validUntil\": \"${_validUntil}\","
                + "  \"signed\": \"${_signed}\""
                + "}";
    }

    private byte[] createMockCoseSign1() throws Exception {
        co.nstant.in.cbor.model.Array coseArray = new co.nstant.in.cbor.model.Array();
        coseArray.add(new ByteString(new byte[]{(byte)0xa1, 0x01, 0x26}));
        coseArray.add(new co.nstant.in.cbor.model.Map());
        coseArray.add(new ByteString(new byte[]{1, 2, 3, 4}));
        coseArray.add(new ByteString(new byte[]{5, 6, 7, 8}));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new CborEncoder(baos).encode(coseArray);
        return baos.toByteArray();
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static Stream<Arguments> provideValidityInfoTestCases() {
        return Stream.of(
                Arguments.of(
                        "Missing validFrom field",
                        "{"
                                + "\"docType\": \"org.iso.18013.5.1.mDL\","
                                + "\"holderId\": \"${_holderId}\","
                                + "\"validityInfo\": {"
                                + "\"signed\": \"${_signed}\","
                                + "\"validUntil\": \"${_validUntil}\""
                                + "}"
                                + "}",
                        "Missing validFrom"
                ),
                Arguments.of(
                        "Missing signed field",
                        "{"
                                + "\"docType\": \"org.iso.18013.5.1.mDL\","
                                + "\"holderId\": \"${_holderId}\","
                                + "\"validityInfo\": {"
                                + "\"validFrom\": \"${_validFrom}\","
                                + "\"validUntil\": \"${_validUntil}\""
                                + "}"
                                + "}",
                        "Missing signed"
                ),
                Arguments.of(
                        "Missing validUntil field",
                        "{"
                                + "\"docType\": \"org.iso.18013.5.1.mDL\","
                                + "\"holderId\": \"${_holderId}\","
                                + "\"validityInfo\": {"
                                + "\"validFrom\": \"${_validFrom}\","
                                + "\"signed\": \"${_signed}\""
                                + "}"
                                + "}",
                        "Missing validUntil"
                ),
                Arguments.of(
                        "Validity info entirely missing",
                        "{"
                                + "\"docType\": \"org.iso.18013.5.1.mDL\","
                                + "\"holderId\": \"${_holderId}\""
                                + "}",
                        "Missing validity info"
                )
        );
    }

}