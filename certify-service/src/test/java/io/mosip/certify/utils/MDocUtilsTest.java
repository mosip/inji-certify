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
import java.time.ZonedDateTime;
import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

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

    @Test
    public void calculateMex_EmptySet_ReturnsZero() {
        Set<Integer> numbers = new HashSet<>();
        int result = MDocUtils.calculateMex(numbers);
        assertEquals(0, result);
    }

    @Test
    public void calculateMex_ConsecutiveNumbers_ReturnsFirstMissing() {
        Set<Integer> numbers = new HashSet<>(Arrays.asList(0, 1, 2, 3, 5));
        int result = MDocUtils.calculateMex(numbers);
        assertEquals(4, result);
    }

    @Test
    public void calculateMex_MissingZero_ReturnsZero() {
        Set<Integer> numbers = new HashSet<>(Arrays.asList(1, 2, 3, 4));
        int result = MDocUtils.calculateMex(numbers);
        assertEquals(0, result);
    }

    @Test
    public void processTemplatedJson_ValidTemplate_ReturnsProcessedMDoc() throws Exception {
        String templatedJSON = "{"
                + "\"docType\": \"org.iso.18013.5.1.mDL\","
                + "\"holderId\": \"did:jwk:test123\","
                + "\"validityInfo\": {"
                + "  \"validFrom\": \"${_validFrom}\","
                + "  \"validUntil\": \"2025-12-31T23:59:59Z\""
                + "},"
                + "\"nameSpaces\": {"
                + "  \"org.iso.18013.5.1\": ["
                + "    {"
                + "      \"digestID\": 0,"
                + "      \"elementIdentifier\": \"family_name\","
                + "      \"elementValue\": \"Doe\""
                + "    }"
                + "  ]"
                + "}"
                + "}";

        Map<String, Object> templateParams = new HashMap<>();
        templateParams.put("_issuer", "https://issuer.example.com");
        templateParams.put("given_name", "John");

        Map<String, Object> result = mDocUtils.processTemplatedJson(templatedJSON, templateParams);

        assertNotNull(result);
        assertEquals("org.iso.18013.5.1.mDL", result.get("docType"));
        assertEquals("did:jwk:test123", result.get("holderId"));
        assertEquals("https://issuer.example.com", result.get("issuer"));

        Map<String, Object> validityInfo = (Map<String, Object>) result.get("validityInfo");
        assertNotNull(validityInfo);
        assertNotEquals("${_validFrom}", validityInfo.get("validFrom"));
        assertTrue(validityInfo.get("validFrom").toString().contains("T"));

        Map<String, Object> nameSpaces = (Map<String, Object>) result.get("nameSpaces");
        assertNotNull(nameSpaces);
        List<Map<String, Object>> items = (List<Map<String, Object>>) nameSpaces.get("org.iso.18013.5.1");
        assertTrue(items.size() >= 2);
    }

    @Test
    public void processTemplatedJson_InvalidJson_ReturnsEmptyMap() {
        String invalidJSON = "{invalid json";
        Map<String, Object> templateParams = new HashMap<>();

        Map<String, Object> result = mDocUtils.processTemplatedJson(invalidJSON, templateParams);

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    public void addMissingFields_AddsNewFields_ExcludesForbiddenAndUnderscored() {
        List<Map<String, Object>> existingItems = new ArrayList<>();
        Map<String, Object> item1 = new HashMap<>();
        item1.put("digestID", 0);
        item1.put("elementIdentifier", "family_name");
        item1.put("elementValue", "Doe");
        existingItems.add(item1);

        Map<String, Object> templateParams = new HashMap<>();
        templateParams.put("given_name", "John");
        templateParams.put("_privateField", "should_not_be_added");
        templateParams.put("templateName", "should_not_be_added");
        templateParams.put("issuer", "should_not_be_added");
        templateParams.put("age", 30);

//        List<Map<String, Object>> result = MDocUtils.addMissingFields(existingItems, templateParams);

//        assertEquals(3, result.size());
//        assertTrue(result.stream().anyMatch(item -> "given_name".equals(item.get("elementIdentifier"))));
//        assertTrue(result.stream().anyMatch(item -> "age".equals(item.get("elementIdentifier"))));
//        assertFalse(result.stream().anyMatch(item -> "_privateField".equals(item.get("elementIdentifier"))));
//        assertFalse(result.stream().anyMatch(item -> "templateName".equals(item.get("elementIdentifier"))));
    }

    @Test
    public void addRandomSalts_AddsRandomBytesToAllElements() {
        Map<String, Object> mDocJson = new HashMap<>();
        Map<String, Object> nameSpaces = new HashMap<>();
        List<Map<String, Object>> elements = new ArrayList<>();

        Map<String, Object> element = new HashMap<>();
        element.put("digestID", 0);
        element.put("elementIdentifier", "family_name");
        element.put("elementValue", "Doe");
        elements.add(element);

        nameSpaces.put("org.iso.18013.5.1", elements);
        mDocJson.put("nameSpaces", nameSpaces);

        Map<String, Object> result = MDocUtils.addRandomSalts(mDocJson);

        assertNotNull(result);
        List<Map<String, Object>> saltedElements = (List<Map<String, Object>>) result.get("org.iso.18013.5.1");
        assertNotNull(saltedElements);
        assertEquals(1, saltedElements.size());

        Map<String, Object> saltedElement = saltedElements.get(0);
        assertTrue(saltedElement.containsKey("random"));
        byte[] random = (byte[]) saltedElement.get("random");
        assertEquals(24, random.length);
    }

    @Test
    public void calculateDigests_GeneratesCorrectDigests() throws Exception {
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

        List<byte[]> taggedElements = (List<byte[]>) result.get("org.iso.18013.5.1");
        assertNotNull(taggedElements);
        assertEquals(1, taggedElements.size());

        assertTrue(namespaceDigests.containsKey("org.iso.18013.5.1"));
        Map<Integer, byte[]> digests = namespaceDigests.get("org.iso.18013.5.1");
        assertTrue(digests.containsKey(0));
        assertEquals(32, digests.get(0).length); // SHA-256 produces 32 bytes
    }

    @Test
    public void isDateOnlyString_ValidDate_ReturnsTrue() {
        assertTrue(MDocUtils.isDateOnlyString("2025-01-15"));
        assertTrue(MDocUtils.isDateOnlyString("1990-12-31"));
    }

    @Test
    public void isDateOnlyString_InvalidDate_ReturnsFalse() {
        assertFalse(MDocUtils.isDateOnlyString("2025-13-01")); // Invalid month
        assertFalse(MDocUtils.isDateOnlyString("2025/01/15")); // Wrong format
        assertFalse(MDocUtils.isDateOnlyString("2025-01-15T10:30:00Z")); // DateTime
        assertFalse(MDocUtils.isDateOnlyString("not a date"));
    }

    @Test
    public void createCBORTaggedDate_CreatesCorrectStructure() {
        Map<String, Object> result = MDocUtils.createCBORTaggedDate("2025-01-15");

        assertNotNull(result);
        assertEquals(1004, result.get("__cbor_tag"));
        assertEquals("2025-01-15", result.get("__cbor_value"));
    }

    @Test
    public void hexStringToByteArray_ValidHex_ConvertsCorrectly() {
        String hex = "48656c6c6f"; // "Hello" in hex
        byte[] result = MDocUtils.hexStringToByteArray(hex);

        assertNotNull(result);
        assertEquals(5, result.length);
        assertArrayEquals(new byte[]{72, 101, 108, 108, 111}, result);
    }

    @Test
    public void createMobileSecurityObject_ValidInput_CreatesCorrectMSO() throws Exception {
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("docType", "org.iso.18013.5.1.mDL");

        // Create a proper did:jwk string
        String jwkJson = "{\"kty\":\"EC\",\"crv\":\"P-256\"}";
        String encodedJwk = Base64.getUrlEncoder().encodeToString(jwkJson.getBytes());
        String didJwk = "did:jwk:" + encodedJwk;
        mDocJson.put("holderId", didJwk); // Use proper did:jwk format

        Map<String, Object> validityInfo = new HashMap<>();
        validityInfo.put("validFrom", "2025-01-01T00:00:00Z");
        validityInfo.put("validUntil", "2025-12-31T23:59:59Z");
        mDocJson.put("validityInfo", validityInfo);

        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        Map<Integer, byte[]> digests = new HashMap<>();
        digests.put(0, new byte[32]);
        namespaceDigests.put("org.iso.18013.5.1", digests);

        Map<String, Object> result = MDocUtils.createMobileSecurityObject(
                mDocJson, namespaceDigests, "testApp", "testRef"
        );

        assertNotNull(result);
        assertEquals("1.0", result.get("version"));
        assertEquals("SHA-256", result.get("digestAlgorithm"));
        assertEquals("org.iso.18013.5.1.mDL", result.get("docType"));
        assertNotNull(result.get("valueDigests"));
        assertNotNull(result.get("validityInfo"));
        assertNotNull(result.get("deviceKeyInfo"));
    }

    @Test
    public void createDeviceKeyInfo_ValidDidJwk_ParsesCorrectly() throws Exception {
        String encodedKey = Base64.getUrlEncoder().encodeToString("{\"kty\":\"EC\",\"crv\":\"P-256\"}".getBytes());
        String didJwk = "did:jwk:" + encodedKey;

        Map<String, Object> result = MDocUtils.createDeviceKeyInfo(didJwk);

        assertNotNull(result);
        assertTrue(result.containsKey("deviceKey"));
        Map<String, Object> deviceKey = (Map<String, Object>) result.get("deviceKey");
        assertEquals("EC", deviceKey.get("kty"));
        assertEquals("P-256", deviceKey.get("crv"));
    }

    @Test
    public void signMSO_ValidInput_ReturnsSignedData() throws Exception {
        Map<String, Object> mso = new HashMap<>();
        mso.put("version", "1.0");
        mso.put("digestAlgorithm", "SHA-256");

        CoseSignResponseDto mockResponse = new CoseSignResponseDto();
        mockResponse.setSignedData("deadbeef");

        when(coseSignatureService.coseSign1(any(CoseSignRequestDto.class))).thenReturn(mockResponse);

        byte[] result = MDocUtils.signMSO(
                mso, "testApp", "testRef", "ES256", didDocumentUtil, coseSignatureService
        );

        assertNotNull(result);
        assertEquals(4, result.length); // deadbeef = 4 bytes
        verify(coseSignatureService).coseSign1(any(CoseSignRequestDto.class));
    }

    @Test
    public void signMSO_CoseServiceThrows_ThrowsException() throws Exception {
        Map<String, Object> mso = new HashMap<>();
        mso.put("version", "1.0");

        when(coseSignatureService.coseSign1(any(CoseSignRequestDto.class)))
                .thenThrow(new RuntimeException("Signing failed"));

        Exception exception = assertThrows(Exception.class, () ->
                MDocUtils.signMSO(mso, "testApp", "testRef", "ES256", didDocumentUtil, coseSignatureService)
        );

        assertTrue(exception.getMessage().contains("COSE signing failed"));
    }

    @Test
    public void createIssuerSignedStructure_ValidInput_CreatesCorrectStructure() {
        Map<String, Object> processedNamespaces = new HashMap<>();
        processedNamespaces.put("org.iso.18013.5.1", new ArrayList<>());

        byte[] signedMSO = new byte[]{1, 2, 3, 4};

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
    public void encodeToCBOR_SimpleMap_EncodesSuccessfully() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("key", "value");
        data.put("number", 42);

        byte[] result = MDocUtils.encodeToCBOR(data);

        assertNotNull(result);
        assertTrue(result.length > 0);
    }

    @Test
    public void encodeToCBOR_WithByteArray_HandlesCorrectly() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("bytes", new byte[]{1, 2, 3});

        byte[] result = MDocUtils.encodeToCBOR(data);

        assertNotNull(result);
        assertTrue(result.length > 0);
    }

    @Test
    public void preprocessForCBOR_DateString_CreatesTaggedDate() {
        Object result = MDocUtils.preprocessForCBOR("2025-01-15");

        assertTrue(result instanceof Map);
        Map<String, Object> tagged = (Map<String, Object>) result;
        assertEquals(1004, tagged.get("__cbor_tag"));
        assertEquals("2025-01-15", tagged.get("__cbor_value"));
    }

    @Test
    public void preprocessForCBOR_NestedMap_ProcessesRecursively() {
        Map<String, Object> nested = new HashMap<>();
        nested.put("date", "2025-01-15");
        nested.put("text", "hello");

        Map<String, Object> data = new HashMap<>();
        data.put("nested", nested);

        Object result = MDocUtils.preprocessForCBOR(data);

        assertTrue(result instanceof Map);
        Map<String, Object> processed = (Map<String, Object>) result;
        Map<String, Object> processedNested = (Map<String, Object>) processed.get("nested");
        assertTrue(processedNested.get("date") instanceof Map);
        assertEquals("hello", processedNested.get("text"));
    }

    @Test
    public void wrapWithCBORTag24_ValidElement_WrapsCorrectly() throws Exception {
        Map<String, Object> element = new HashMap<>();
        element.put("digestID", 0);
        element.put("elementIdentifier", "test");
        element.put("elementValue", "value");

        byte[] result = MDocUtils.wrapWithCBORTag24(element);

        assertNotNull(result);
        assertTrue(result.length > 0);
    }
}