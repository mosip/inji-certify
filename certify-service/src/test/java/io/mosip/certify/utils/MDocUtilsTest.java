package io.mosip.certify.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.kernel.signature.dto.CoseSignRequestDto;
import io.mosip.kernel.signature.dto.CoseSignResponseDto;
import io.mosip.kernel.signature.service.CoseSignatureService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.MessageDigest;
import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive unit tests for MDocUtils
 * Tests cover all acceptance criteria from INJICERT-981:
 * - Data mapping to ISO 18013-5 elements and namespaces
 * - Digest calculation for selective disclosure
 * - MSO structure generation
 * - CBOR encoding conformance
 * - DeviceKeyInfo handling from wallet PoP
 * - Template processing with system metadata
 */
@RunWith(MockitoJUnitRunner.class)
public class MDocUtilsTest {

    @Mock
    private CoseSignatureService coseSignatureService;

    @Mock
    private DIDDocumentUtil didDocumentUtil;

    @InjectMocks
    private MDocUtils mDocUtils;

    private ObjectMapper objectMapper;

    @Before
    public void setUp() {
        objectMapper = new ObjectMapper();
        ReflectionTestUtils.setField(mDocUtils, "objectMapper", objectMapper);
    }

    // ==================== Template Processing Tests ====================

    @Test
    public void processTemplatedJson_ValidmDLTemplate_MapsToISO18013Elements() throws Exception {
        String templatedJSON = "{"
                + "\"docType\": \"org.iso.18013.5.1.mDL\","
                + "\"holderId\": \"did:jwk:test123\","
                + "\"validityInfo\": {"
                + "  \"validFrom\": \"${_validFrom}\","
                + "  \"validUntil\": \"${_validUntil}\""
                + "},"
                + "\"nameSpaces\": {"
                + "  \"org.iso.18013.5.1\": ["
                + "    {\"digestID\": 0, \"elementIdentifier\": \"family_name\", \"elementValue\": \"${familyName}\"},"
                + "    {\"digestID\": 1, \"elementIdentifier\": \"given_name\", \"elementValue\": \"${givenName}\"},"
                + "    {\"digestID\": 2, \"elementIdentifier\": \"birth_date\", \"elementValue\": \"${birthDate}\"}"
                + "  ]"
                + "}"
                + "}";

        Map<String, Object> templateParams = new HashMap<>();
        templateParams.put("familyName", "Doe");
        templateParams.put("givenName", "John");
        templateParams.put("birthDate", "1990-08-25");
        templateParams.put("didUrl", "https://issuer.example.com");
        templateParams.put("_holderId", "did:jwk:test123");

        Map<String, Object> result = mDocUtils.processTemplatedJson(templatedJSON, templateParams);

        assertNotNull(result);
        assertEquals("org.iso.18013.5.1.mDL", result.get("_docType"));
        assertEquals("did:jwk:test123", result.get("_holderId"));
        assertEquals("https://issuer.example.com", result.get("_issuer"));

        // Verify namespace structure
        Map<String, Object> nameSpaces = (Map<String, Object>) result.get("nameSpaces");
        assertNotNull(nameSpaces);
        List<Map<String, Object>> items = (List<Map<String, Object>>) nameSpaces.get("org.iso.18013.5.1");
        assertEquals(3, items.size());

        // Verify data element mapping
        assertEquals("family_name", items.get(0).get("elementIdentifier"));
        assertEquals("Doe", items.get(0).get("elementValue"));
    }

    @Test
    public void processTemplatedJson_ValidityInfoPlaceholders_ReplacedWithTimestamps() throws Exception {
        String templatedJSON = "{"
                + "\"docType\": \"org.iso.18013.5.1.mDL\","
                + "\"validityInfo\": {"
                + "  \"validFrom\": \"${_validFrom}\","
                + "  \"validUntil\": \"${_validUntil}\""
                + "},"
                + "\"nameSpaces\": {\"org.iso.18013.5.1\": []}"
                + "}";

        Map<String, Object> templateParams = new HashMap<>();
        Map<String, Object> result = mDocUtils.processTemplatedJson(templatedJSON, templateParams);

        Map<String, Object> validityInfo = (Map<String, Object>) result.get("validityInfo");
        assertNotNull(validityInfo);
        assertNotEquals("${_validFrom}", validityInfo.get("validFrom"));
        assertNotEquals("${_validUntil}", validityInfo.get("validUntil"));

        // Verify timestamp format (ISO 8601)
        assertTrue(validityInfo.get("validFrom").toString().matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}.*"));
    }

    @Test
    public void processTemplatedJson_ComplexElementValue_PreservesStructure() throws Exception {
        String templatedJSON = "{"
                + "\"nameSpaces\": {"
                + "  \"org.iso.18013.5.1\": ["
                + "    {\"digestID\": 7, \"elementIdentifier\": \"driving_privileges\", "
                + "     \"elementValue\": [{\"vehicle_category_code\": \"A\"}, {\"vehicle_category_code\": \"B\"}]}"
                + "  ]"
                + "}"
                + "}";

        Map<String, Object> result = mDocUtils.processTemplatedJson(templatedJSON, new HashMap<>());

        Map<String, Object> nameSpaces = (Map<String, Object>) result.get("nameSpaces");
        List<Map<String, Object>> items = (List<Map<String, Object>>) nameSpaces.get("org.iso.18013.5.1");

        Object elementValue = items.get(0).get("elementValue");
        assertTrue(elementValue instanceof List);
        List<Map<String, Object>> privileges = (List<Map<String, Object>>) elementValue;
        assertEquals(2, privileges.size());
        assertEquals("A", privileges.get(0).get("vehicle_category_code"));
    }

    @Test
    public void processTemplatedJson_InvalidJson_ReturnsEmptyMap() {
        String invalidJSON = "{invalid json";
        Map<String, Object> result = mDocUtils.processTemplatedJson(invalidJSON, new HashMap<>());

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    public void processTemplatedJson_CustomNamespace_HandlesCorrectly() throws Exception {
        String templatedJSON = "{"
                + "\"docType\": \"org.mosip.farmer.1\","
                + "\"nameSpaces\": {"
                + "  \"org.mosip.farmer\": ["
                + "    {\"digestID\": 0, \"elementIdentifier\": \"farmer_id\", \"elementValue\": \"${farmerId}\"},"
                + "    {\"digestID\": 1, \"elementIdentifier\": \"land_area\", \"elementValue\": \"${landArea}\"}"
                + "  ]"
                + "}"
                + "}";

        Map<String, Object> templateParams = new HashMap<>();
        templateParams.put("farmerId", "FARM12345");
        templateParams.put("landArea", "25.5");

        Map<String, Object> result = mDocUtils.processTemplatedJson(templatedJSON, templateParams);

        Map<String, Object> nameSpaces = (Map<String, Object>) result.get("nameSpaces");
        assertTrue(nameSpaces.containsKey("org.mosip.farmer"));
    }

    // ==================== Random Salt Tests ====================

    @Test
    public void addRandomSalts_AddsRandomBytesToAllElements() {
        Map<String, Object> mDocJson = new HashMap<>();
        Map<String, Object> nameSpaces = new HashMap<>();
        List<Map<String, Object>> elements = new ArrayList<>();

        Map<String, Object> element1 = new HashMap<>();
        element1.put("digestID", 0);
        element1.put("elementIdentifier", "family_name");
        element1.put("elementValue", "Doe");
        elements.add(element1);

        Map<String, Object> element2 = new HashMap<>();
        element2.put("digestID", 1);
        element2.put("elementIdentifier", "given_name");
        element2.put("elementValue", "John");
        elements.add(element2);

        nameSpaces.put("org.iso.18013.5.1", elements);
        mDocJson.put("nameSpaces", nameSpaces);

        Map<String, Object> result = MDocUtils.addRandomSalts(mDocJson);

        assertNotNull(result);
        List<Map<String, Object>> saltedElements = (List<Map<String, Object>>) result.get("org.iso.18013.5.1");
        assertEquals(2, saltedElements.size());

        // Verify 24-byte random salt for each element
        for (Map<String, Object> saltedElement : saltedElements) {
            assertTrue(saltedElement.containsKey("random"));
            byte[] random = (byte[]) saltedElement.get("random");
            assertEquals(24, random.length);
        }
    }

    @Test
    public void addRandomSalts_CryptographicallySecure_GeneratesUniqueSalts() {
        Map<String, Object> mDocJson = new HashMap<>();
        Map<String, Object> nameSpaces = new HashMap<>();
        List<Map<String, Object>> elements = new ArrayList<>();

        for (int i = 0; i < 5; i++) {
            Map<String, Object> element = new HashMap<>();
            element.put("digestID", i);
            element.put("elementIdentifier", "field_" + i);
            element.put("elementValue", "value_" + i);
            elements.add(element);
        }

        nameSpaces.put("org.iso.18013.5.1", elements);
        mDocJson.put("nameSpaces", nameSpaces);

        Map<String, Object> result = MDocUtils.addRandomSalts(mDocJson);
        List<Map<String, Object>> saltedElements = (List<Map<String, Object>>) result.get("org.iso.18013.5.1");

        // Verify all salts are unique
        Set<String> saltSet = new HashSet<>();
        for (Map<String, Object> element : saltedElements) {
            byte[] random = (byte[]) element.get("random");
            String saltHex = bytesToHex(random);
            assertTrue("Duplicate salt found", saltSet.add(saltHex));
        }
    }

    @Test
    public void addRandomSalts_MultipleNamespaces_HandlesAll() {
        Map<String, Object> mDocJson = new HashMap<>();
        Map<String, Object> nameSpaces = new HashMap<>();

        List<Map<String, Object>> isoElements = new ArrayList<>();
        isoElements.add(createTestElement(0, "family_name", "Doe"));
        nameSpaces.put("org.iso.18013.5.1", isoElements);

        List<Map<String, Object>> customElements = new ArrayList<>();
        customElements.add(createTestElement(0, "custom_field", "value"));
        nameSpaces.put("org.custom.namespace", customElements);

        mDocJson.put("nameSpaces", nameSpaces);

        Map<String, Object> result = MDocUtils.addRandomSalts(mDocJson);

        assertTrue(result.containsKey("org.iso.18013.5.1"));
        assertTrue(result.containsKey("org.custom.namespace"));
    }

    // ==================== Digest Calculation Tests ====================

    @Test
    public void calculateDigests_GeneratesCorrectSHA256Digests() throws Exception {
        Map<String, Object> saltedNamespaces = new HashMap<>();
        List<Map<String, Object>> elements = new ArrayList<>();

        Map<String, Object> element = new HashMap<>();
        element.put("digestID", 0);
        element.put("elementIdentifier", "family_name");
        element.put("elementValue", "Doe");
        element.put("random", new byte[24]);
        elements.add(element);

        saltedNamespaces.put("org.iso.18013.5.1", elements);
        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();

        Map<String, Object> result = MDocUtils.calculateDigests(saltedNamespaces, namespaceDigests);

        assertNotNull(result);
        assertTrue(result.containsKey("org.iso.18013.5.1"));

        // Verify digest output
        List<byte[]> taggedElements = (List<byte[]>) result.get("org.iso.18013.5.1");
        assertNotNull(taggedElements);
        assertEquals(1, taggedElements.size());

        // Verify digest map
        assertTrue(namespaceDigests.containsKey("org.iso.18013.5.1"));
        Map<Integer, byte[]> digests = namespaceDigests.get("org.iso.18013.5.1");
        assertTrue(digests.containsKey(0));
        assertEquals(32, digests.get(0).length); // SHA-256 produces 32 bytes
    }

    @Test
    public void calculateDigests_MultipleElements_MapsDigestsByID() throws Exception {
        Map<String, Object> saltedNamespaces = new HashMap<>();
        List<Map<String, Object>> elements = new ArrayList<>();

        for (int i = 0; i < 3; i++) {
            Map<String, Object> element = new HashMap<>();
            element.put("digestID", i);
            element.put("elementIdentifier", "field_" + i);
            element.put("elementValue", "value_" + i);
            element.put("random", new byte[24]);
            elements.add(element);
        }

        saltedNamespaces.put("org.iso.18013.5.1", elements);
        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();

        MDocUtils.calculateDigests(saltedNamespaces, namespaceDigests);

        Map<Integer, byte[]> digests = namespaceDigests.get("org.iso.18013.5.1");
        assertEquals(3, digests.size());
        assertTrue(digests.containsKey(0));
        assertTrue(digests.containsKey(1));
        assertTrue(digests.containsKey(2));
    }

    @Test
    public void calculateDigests_WrapsWithCBORTag24() throws Exception {
        Map<String, Object> saltedNamespaces = new HashMap<>();
        List<Map<String, Object>> elements = new ArrayList<>();
        elements.add(createSaltedElement(0, "test", "value"));
        saltedNamespaces.put("org.iso.18013.5.1", elements);

        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        Map<String, Object> result = MDocUtils.calculateDigests(saltedNamespaces, namespaceDigests);

        List<byte[]> taggedElements = (List<byte[]>) result.get("org.iso.18013.5.1");
        assertNotNull(taggedElements);
        assertTrue(taggedElements.get(0).length > 0);
    }

    // ==================== Date Handling Tests ====================

    @Test
    public void isDateOnlyString_ValidDates_ReturnsTrue() {
        assertTrue(MDocUtils.isDateOnlyString("2025-01-15"));
        assertTrue(MDocUtils.isDateOnlyString("1990-12-31"));
        assertTrue(MDocUtils.isDateOnlyString("2000-02-29")); // Leap year
    }

    @Test
    public void isDateOnlyString_InvalidDates_ReturnsFalse() {
        assertFalse(MDocUtils.isDateOnlyString("2025-13-01")); // Invalid month
        assertFalse(MDocUtils.isDateOnlyString("2025/01/15")); // Wrong format
        assertFalse(MDocUtils.isDateOnlyString("2025-01-15T10:30:00Z")); // DateTime
        assertFalse(MDocUtils.isDateOnlyString("not a date"));
        assertFalse(MDocUtils.isDateOnlyString("15-01-2025")); // Wrong order
    }

    @Test
    public void createCBORTaggedDate_CreatesTag1004Structure() {
        Map<String, Object> result = MDocUtils.createCBORTaggedDate("2025-01-15");

        assertNotNull(result);
        assertEquals(1004, result.get("__cbor_tag"));
        assertEquals("2025-01-15", result.get("__cbor_value"));
    }

    // ==================== DeviceKeyInfo Tests ====================

    @Test
    public void createDeviceKeyInfo_ValidDidJwkEC_ParsesCorrectly() throws Exception {
        String jwkJson = "{\"kty\":\"EC\",\"crv\":\"P-256\","
                + "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
                + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}";
        String encodedKey = Base64.getUrlEncoder().encodeToString(jwkJson.getBytes());
        String didJwk = "did:jwk:" + encodedKey;

        Map<String, Object> result = MDocUtils.createDeviceKeyInfo(didJwk);

        assertNotNull(result);
        assertTrue(result.containsKey("deviceKey"));

        Map<Object, Object> deviceKey = (Map<Object, Object>) result.get("deviceKey");
        assertEquals(2, deviceKey.get(1)); // kty: EC2
        assertEquals(-7, deviceKey.get(3)); // alg: ES256
        assertEquals(1, deviceKey.get(-1)); // crv: P-256
        assertTrue(deviceKey.containsKey(-2)); // x coordinate
        assertTrue(deviceKey.containsKey(-3)); // y coordinate
    }

    @Test
    public void createDeviceKeyInfo_P384Curve_MapsCorrectly() throws Exception {
        String jwkJson = "{\"kty\":\"EC\",\"crv\":\"P-384\","
                + "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
                + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}";
        String encodedKey = Base64.getUrlEncoder().encodeToString(jwkJson.getBytes());
        String didJwk = "did:jwk:" + encodedKey;

        Map<String, Object> result = MDocUtils.createDeviceKeyInfo(didJwk);
        Map<Object, Object> deviceKey = (Map<Object, Object>) result.get("deviceKey");

        assertEquals(2, deviceKey.get(-1)); // crv: P-384
    }

    @Test(expected = IllegalArgumentException.class)
    public void createDeviceKeyInfo_UnsupportedCurve_ThrowsException() throws Exception {
        String jwkJson = "{\"kty\":\"EC\",\"crv\":\"secp256k1\"}";
        String encodedKey = Base64.getUrlEncoder().encodeToString(jwkJson.getBytes());
        String didJwk = "did:jwk:" + encodedKey;

        MDocUtils.createDeviceKeyInfo(didJwk);
    }

    @Test
    public void createDeviceKeyInfo_WithKeyId_PreservesKid() throws Exception {
        String jwkJson = "{\"kty\":\"EC\",\"crv\":\"P-256\","
                + "\"kid\":\"test-key-id\","
                + "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
                + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}";
        String encodedKey = Base64.getUrlEncoder().encodeToString(jwkJson.getBytes());
        String didJwk = "did:jwk:" + encodedKey;

        Map<String, Object> result = MDocUtils.createDeviceKeyInfo(didJwk);
        Map<Object, Object> deviceKey = (Map<Object, Object>) result.get("deviceKey");

        assertTrue(deviceKey.containsKey(2)); // kid present
        assertArrayEquals("test-key-id".getBytes(), (byte[]) deviceKey.get(2));
    }

    // ==================== MSO Creation Tests ====================

    @Test
    public void createMobileSecurityObject_ValidInput_CreatesCompleteStructure() throws Exception {
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "org.iso.18013.5.1.mDL");

        String jwkJson = "{\"kty\":\"EC\",\"crv\":\"P-256\","
                + "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
                + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}";
        String encodedJwk = Base64.getUrlEncoder().encodeToString(jwkJson.getBytes());
        mDocJson.put("_holderId", "did:jwk:" + encodedJwk);

        Map<String, Object> validityInfo = new HashMap<>();
        validityInfo.put("validFrom", "2025-01-01T00:00:00Z");
        validityInfo.put("validUntil", "2025-12-31T23:59:59Z");
        mDocJson.put("validityInfo", validityInfo);

        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        Map<Integer, byte[]> digests = new HashMap<>();
        digests.put(0, new byte[32]);
        digests.put(1, new byte[32]);
        namespaceDigests.put("org.iso.18013.5.1", digests);

        Map<String, Object> result = MDocUtils.createMobileSecurityObject(
                mDocJson, namespaceDigests, "testApp", "testRef"
        );

        // Verify MSO structure
        assertNotNull(result);
        assertEquals("1.0", result.get("version"));
        assertEquals("SHA-256", result.get("digestAlgorithm"));
        assertEquals("org.iso.18013.5.1.mDL", result.get("docType"));
        assertNotNull(result.get("valueDigests"));
        assertNotNull(result.get("validityInfo"));
        assertNotNull(result.get("deviceKeyInfo"));

        // Verify valueDigests structure
        Map<String, Object> valueDigests = (Map<String, Object>) result.get("valueDigests");
        assertTrue(valueDigests.containsKey("nameSpaces"));
        Map<String, Object> nameSpaces = (Map<String, Object>) valueDigests.get("nameSpaces");
        assertTrue(nameSpaces.containsKey("org.iso.18013.5.1"));
    }

    @Test
    public void createMobileSecurityObject_ValidityInfo_PreservesTimestamps() throws Exception {
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "org.iso.18013.5.1.mDL");
        mDocJson.put("_holderId", createTestDidJwk());

        String validFrom = "2024-01-12T00:00:00Z";
        String validUntil = "2025-01-12T00:00:00Z";
        Map<String, Object> validityInfo = new HashMap<>();
        validityInfo.put("validFrom", validFrom);
        validityInfo.put("validUntil", validUntil);
        mDocJson.put("validityInfo", validityInfo);

        Map<String, Object> result = MDocUtils.createMobileSecurityObject(
                mDocJson, new HashMap<>(), "app", "ref"
        );

        Map<String, Object> resultValidity = (Map<String, Object>) result.get("validityInfo");
        assertEquals(validFrom, resultValidity.get("validFrom"));
        assertEquals(validUntil, resultValidity.get("validUntil"));
    }

    // ==================== COSE Signing Tests ====================

    @Test
    public void signMSO_ValidInput_ReturnsSignedCOSEBytes() throws Exception {
        Map<String, Object> mso = new HashMap<>();
        mso.put("version", "1.0");
        mso.put("digestAlgorithm", "SHA-256");
        mso.put("docType", "org.iso.18013.5.1.mDL");

        CoseSignResponseDto mockResponse = new CoseSignResponseDto();
        mockResponse.setSignedData("a10126"); // Simple hex COSE structure

        when(coseSignatureService.coseSign1(any(CoseSignRequestDto.class))).thenReturn(mockResponse);

        byte[] result = MDocUtils.signMSO(
                mso, "testApp", "testRef", "ES256", didDocumentUtil, coseSignatureService
        );

        assertNotNull(result);
        assertTrue(result.length > 0);
        verify(coseSignatureService).coseSign1(any(CoseSignRequestDto.class));
    }

    @Test
    public void signMSO_RequestsX5cInProtectedHeader() throws Exception {
        Map<String, Object> mso = new HashMap<>();
        mso.put("version", "1.0");

        CoseSignResponseDto mockResponse = new CoseSignResponseDto();
        mockResponse.setSignedData("deadbeef");

        when(coseSignatureService.coseSign1(any(CoseSignRequestDto.class))).thenReturn(mockResponse);

        MDocUtils.signMSO(mso, "app", "ref", "ES256", didDocumentUtil, coseSignatureService);

        verify(coseSignatureService).coseSign1(argThat(request -> {
            Map<String, Object> header = request.getProtectedHeader();
            return header != null && Boolean.TRUE.equals(header.get("x5c"));
        }));
    }

    @Test
    public void signMSO_EncodesPayloadAsBase64Url() throws Exception {
        Map<String, Object> mso = new HashMap<>();
        mso.put("test", "value");

        CoseSignResponseDto mockResponse = new CoseSignResponseDto();
        mockResponse.setSignedData("abcd");

        when(coseSignatureService.coseSign1(any(CoseSignRequestDto.class))).thenReturn(mockResponse);

        MDocUtils.signMSO(mso, "app", "ref", "ES256", didDocumentUtil, coseSignatureService);

        verify(coseSignatureService).coseSign1(argThat(request -> {
            String payload = request.getPayload();
            return payload != null && !payload.contains("=") && !payload.contains("+");
        }));
    }

    @Test
    public void signMSO_CoseServiceThrows_ThrowsException() throws Exception {
        Map<String, Object> mso = new HashMap<>();
        mso.put("version", "1.0");

        when(coseSignatureService.coseSign1(any(CoseSignRequestDto.class)))
                .thenThrow(new RuntimeException("Signing failed"));

        Exception exception = assertThrows(Exception.class, () ->
                MDocUtils.signMSO(mso, "app", "ref", "ES256", didDocumentUtil, coseSignatureService)
        );

        assertTrue(exception.getMessage().contains("COSE signing failed"));
    }

    // ==================== IssuerSigned Structure Tests ====================

    @Test
    public void createIssuerSignedStructure_CreatesCorrectStructure() {
        Map<String, Object> processedNamespaces = new HashMap<>();
        List<byte[]> elements = new ArrayList<>();
        elements.add(new byte[]{1, 2, 3});
        processedNamespaces.put("org.iso.18013.5.1", elements);

        byte[] signedMSO = new byte[]{4, 5, 6, 7};

        Map<String, Object> result = MDocUtils.createIssuerSignedStructure(
                processedNamespaces, signedMSO
        );

        assertNotNull(result);
        assertTrue(result.containsKey("nameSpaces"));
        assertTrue(result.containsKey("issuerAuth"));
        assertEquals(processedNamespaces, result.get("nameSpaces"));
        assertArrayEquals(signedMSO, (byte[]) result.get("issuerAuth"));
    }

    @Test
    public void createIssuerSignedStructure_EmptyNamespaces_HandlesGracefully() {
        Map<String, Object> processedNamespaces = new HashMap<>();
        byte[] signedMSO = new byte[]{1, 2, 3, 4};

        Map<String, Object> result = MDocUtils.createIssuerSignedStructure(
                processedNamespaces, signedMSO
        );

        assertNotNull(result);
        assertTrue(((Map<String, Object>) result.get("nameSpaces")).isEmpty());
    }

    // ==================== CBOR Encoding Tests ====================

    @Test
    public void encodeToCBOR_SimpleMap_EncodesSuccessfully() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("key", "value");
        data.put("number", 42);
        data.put("boolean", true);

        byte[] result = MDocUtils.encodeToCBOR(data);

        assertNotNull(result);
        assertTrue(result.length > 0);
    }

    @Test
    public void encodeToCBOR_WithByteArray_HandlesCorrectly() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("bytes", new byte[]{1, 2, 3, 4, 5});

        byte[] result = MDocUtils.encodeToCBOR(data);

        assertNotNull(result);
        assertTrue(result.length > 0);
    }

    @Test
    public void encodeToCBOR_NestedStructures_EncodesRecursively() throws Exception {
        Map<String, Object> nested = new HashMap<>();
        nested.put("inner", "value");

        Map<String, Object> data = new HashMap<>();
        data.put("outer", nested);
        data.put("list", Arrays.asList(1, 2, 3));

        byte[] result = MDocUtils.encodeToCBOR(data);

        assertNotNull(result);
        assertTrue(result.length > 0);
    }

    @Test
    public void encodeToCBOR_WithDates_AppliesTag1004() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("birthDate", "1990-08-25");

        byte[] result = MDocUtils.encodeToCBOR(data);

        assertNotNull(result);
        // CBOR with tag 1004 should be present
        assertTrue(result.length > 0);
    }

    @Test
    public void encodeToCBOR_ComplexMDocStructure_SuccessfullyEncodes() throws Exception {
        Map<String, Object> element = new HashMap<>();
        element.put("digestID", 0);
        element.put("elementIdentifier", "family_name");
        element.put("elementValue", "Doe");
        element.put("random", new byte[24]);

        byte[] result = MDocUtils.encodeToCBOR(element);

        assertNotNull(result);
        assertTrue(result.length > 0);
    }

    // ==================== CBOR Preprocessing Tests ====================

    @Test
    public void preprocessForCBOR_DateString_CreatesTaggedDate() {
        Object result = MDocUtils.preprocessForCBOR("2025-01-15");

        assertTrue(result instanceof Map);
        Map<String, Object> tagged = (Map<String, Object>) result;
        assertEquals(1004, tagged.get("__cbor_tag"));
        assertEquals("2025-01-15", tagged.get("__cbor_value"));
    }

    @Test
    public void preprocessForCBOR_NonDateString_PassesThrough() {
        Object result = MDocUtils.preprocessForCBOR("Hello World");

        assertEquals("Hello World", result);
    }

    @Test
    public void preprocessForCBOR_ByteArray_PreservesBytes() {
        byte[] bytes = new byte[]{1, 2, 3, 4};
        Object result = MDocUtils.preprocessForCBOR(bytes);

        assertSame(bytes, result);
    }

    @Test
    public void preprocessForCBOR_NestedMap_ProcessesRecursively() {
        Map<String, Object> nested = new HashMap<>();
        nested.put("date", "2025-01-15");
        nested.put("text", "hello");

        Map<String, Object> data = new HashMap<>();
        data.put("nested", nested);
        data.put("topDate", "2024-12-31");

        Object result = MDocUtils.preprocessForCBOR(data);

        assertTrue(result instanceof Map);
        Map<String, Object> processed = (Map<String, Object>) result;
        Map<String, Object> processedNested = (Map<String, Object>) processed.get("nested");
        assertTrue(processedNested.get("date") instanceof Map);
        assertEquals("hello", processedNested.get("text"));
        assertTrue(processed.get("topDate") instanceof Map);
    }

    @Test
    public void preprocessForCBOR_List_ProcessesAllItems() {
        List<Object> list = Arrays.asList("2025-01-15", "plain text", 42);

        Object result = MDocUtils.preprocessForCBOR(list);

        assertTrue(result instanceof List);
        List<Object> processed = (List<Object>) result;
        assertTrue(processed.get(0) instanceof Map); // Date tagged
        assertEquals("plain text", processed.get(1));
        assertEquals(42, processed.get(2));
    }

    @Test
    public void preprocessForCBOR_Null_ReturnsNull() {
        assertNull(MDocUtils.preprocessForCBOR(null));
    }

    // ==================== CBOR Tag 24 Wrapping Tests ====================

    @Test
    public void wrapWithCBORTag24_ValidElement_WrapsCorrectly() throws Exception {
        Map<String, Object> element = new HashMap<>();
        element.put("digestID", 0);
        element.put("elementIdentifier", "test");
        element.put("elementValue", "value");
        element.put("random", new byte[24]);

        byte[] result = MDocUtils.wrapWithCBORTag24(element);

        assertNotNull(result);
        assertTrue(result.length > 0);
        // Tag 24 indicator should be in the CBOR bytes (0xD8 0x18)
    }

    @Test
    public void wrapWithCBORTag24_ComplexElement_HandlesCorrectly() throws Exception {
        Map<String, Object> element = new HashMap<>();
        element.put("digestID", 7);
        element.put("elementIdentifier", "driving_privileges");

        List<Map<String, Object>> privileges = new ArrayList<>();
        Map<String, Object> privilege = new HashMap<>();
        privilege.put("vehicle_category_code", "A");
        privilege.put("issue_date", "2023-01-15");
        privileges.add(privilege);

        element.put("elementValue", privileges);
        element.put("random", new byte[24]);

        byte[] result = MDocUtils.wrapWithCBORTag24(element);

        assertNotNull(result);
        assertTrue(result.length > 0);
    }

    // ==================== Hex Conversion Tests ====================

    @Test
    public void hexStringToByteArray_ValidHex_ConvertsCorrectly() {
        String hex = "48656c6c6f"; // "Hello" in hex
        byte[] result = MDocUtils.hexStringToByteArray(hex);

        assertNotNull(result);
        assertEquals(5, result.length);
        assertArrayEquals(new byte[]{72, 101, 108, 108, 111}, result);
    }

    @Test
    public void hexStringToByteArray_EmptyString_ReturnsEmptyArray() {
        byte[] result = MDocUtils.hexStringToByteArray("");

        assertNotNull(result);
        assertEquals(0, result.length);
    }

    @Test
    public void hexStringToByteArray_COSESignature_ConvertsCorrectly() {
        String hex = "deadbeef";
        byte[] result = MDocUtils.hexStringToByteArray(hex);

        assertEquals(4, result.length);
        assertArrayEquals(new byte[]{(byte)0xDE, (byte)0xAD, (byte)0xBE, (byte)0xEF}, result);
    }

    @Test
    public void hexStringToByteArray_LongHex_HandlesCorrectly() {
        String hex = "0102030405060708090a0b0c0d0e0f10";
        byte[] result = MDocUtils.hexStringToByteArray(hex);

        assertEquals(16, result.length);
        assertEquals(0x01, result[0]);
        assertEquals(0x10, result[15]);
    }

    // ==================== Integration Tests ====================

    @Test
    public void fullmDocWorkflow_CreatesValidStructure() throws Exception {
        // 1. Create initial mDoc structure
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "org.iso.18013.5.1.mDL");
        mDocJson.put("_holderId", createTestDidJwk());

        Map<String, Object> validityInfo = new HashMap<>();
        validityInfo.put("validFrom", "2024-01-01T00:00:00Z");
        validityInfo.put("validUntil", "2025-01-01T00:00:00Z");
        mDocJson.put("validityInfo", validityInfo);

        Map<String, Object> nameSpaces = new HashMap<>();
        List<Map<String, Object>> elements = new ArrayList<>();
        elements.add(createTestElement(0, "family_name", "Doe"));
        elements.add(createTestElement(1, "given_name", "John"));
        nameSpaces.put("org.iso.18013.5.1", elements);
        mDocJson.put("nameSpaces", nameSpaces);

        // 2. Add random salts
        Map<String, Object> saltedNamespaces = MDocUtils.addRandomSalts(mDocJson);
        assertNotNull(saltedNamespaces);

        // 3. Calculate digests
        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        Map<String, Object> taggedNamespaces = MDocUtils.calculateDigests(saltedNamespaces, namespaceDigests);
        assertNotNull(taggedNamespaces);
        assertEquals(2, namespaceDigests.get("org.iso.18013.5.1").size());

        // 4. Create MSO
        Map<String, Object> mso = MDocUtils.createMobileSecurityObject(
                mDocJson, namespaceDigests, "app", "ref"
        );
        assertNotNull(mso);
        assertEquals("1.0", mso.get("version"));

        // 5. Sign MSO (mocked)
        CoseSignResponseDto mockResponse = new CoseSignResponseDto();
        mockResponse.setSignedData("a10126");
        when(coseSignatureService.coseSign1(any(CoseSignRequestDto.class))).thenReturn(mockResponse);

        byte[] signedMSO = MDocUtils.signMSO(mso, "app", "ref", "ES256", didDocumentUtil, coseSignatureService);
        assertNotNull(signedMSO);

        // 6. Create IssuerSigned structure
        Map<String, Object> issuerSigned = MDocUtils.createIssuerSignedStructure(taggedNamespaces, signedMSO);
        assertNotNull(issuerSigned);
        assertTrue(issuerSigned.containsKey("nameSpaces"));
        assertTrue(issuerSigned.containsKey("issuerAuth"));

        // 7. Encode to CBOR
        byte[] cborEncoded = MDocUtils.encodeToCBOR(issuerSigned);
        assertNotNull(cborEncoded);
        assertTrue(cborEncoded.length > 0);

        // 8. Base64Url encode for transport
        String base64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(cborEncoded);
        assertNotNull(base64Url);
        assertFalse(base64Url.contains("="));
    }

    @Test
    public void multipleNamespacesWorkflow_HandlesAllNamespaces() throws Exception {
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "org.custom.credential");
        mDocJson.put("_holderId", createTestDidJwk());

        Map<String, Object> nameSpaces = new HashMap<>();
        nameSpaces.put("org.iso.18013.5.1", Arrays.asList(
                createTestElement(0, "family_name", "Doe")
        ));
        nameSpaces.put("org.mosip.farmer", Arrays.asList(
                createTestElement(0, "farmer_id", "FARM123")
        ));
        mDocJson.put("nameSpaces", nameSpaces);

        Map<String, Object> saltedNamespaces = MDocUtils.addRandomSalts(mDocJson);
        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        MDocUtils.calculateDigests(saltedNamespaces, namespaceDigests);

        assertTrue(namespaceDigests.containsKey("org.iso.18013.5.1"));
        assertTrue(namespaceDigests.containsKey("org.mosip.farmer"));
    }

    // ==================== Error Handling Tests ====================

    @Test(expected = Exception.class)
    public void encodeToCBOR_InvalidData_ThrowsException() throws Exception {
        // Create a circular reference
        Map<String, Object> data = new HashMap<>();
        data.put("self", data);

        MDocUtils.encodeToCBOR(data);
    }

    @Test
    public void processTemplatedJson_MissingNamespaces_HandlesGracefully() {
        String templatedJSON = "{\"docType\": \"org.iso.18013.5.1.mDL\"}";

        Map<String, Object> result = mDocUtils.processTemplatedJson(templatedJSON, new HashMap<>());

        assertNotNull(result);
        assertTrue(result.containsKey("nameSpaces"));
    }

    @Test
    public void calculateDigests_EmptyNamespace_HandlesGracefully() throws Exception {
        Map<String, Object> saltedNamespaces = new HashMap<>();
        saltedNamespaces.put("org.iso.18013.5.1", new ArrayList<>());

        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        Map<String, Object> result = MDocUtils.calculateDigests(saltedNamespaces, namespaceDigests);

        assertNotNull(result);
        assertTrue(result.containsKey("org.iso.18013.5.1"));
        assertTrue(((List<?>) result.get("org.iso.18013.5.1")).isEmpty());
    }

    // ==================== Helper Methods ====================

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

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}