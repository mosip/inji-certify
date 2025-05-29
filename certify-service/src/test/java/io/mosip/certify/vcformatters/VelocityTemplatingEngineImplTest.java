package io.mosip.certify.vcformatters;

import java.util.*;


import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.TemplateId; // Import TemplateId
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Assert;

import static io.mosip.certify.core.constants.Constants.DELIMITER;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.core.spi.RenderingTemplateService;

import lombok.SneakyThrows;
import net.javacrumbs.jsonunit.assertj.JsonAssertions;


@RunWith(MockitoJUnitRunner.class)
public class VelocityTemplatingEngineImplTest {
    @InjectMocks
    private VelocityTemplatingEngineImpl formatter;
    @Mock
    CredentialConfigRepository credentialConfigRepository;
    @Mock
    RenderingTemplateService renderingTemplateService;

    private CredentialConfig vc2;
    private CredentialConfig vc3;
    private CredentialConfig vc4;

    // Template Keys used in tests, derived from CredentialConfig objects
    private String vc2TemplateKey;
    private TemplateId vc2TemplateIdObject;

    private String vc3TemplateKey;
    private TemplateId vc3TemplateIdObject;

    private String vc4TemplateKey;
    private TemplateId vc4TemplateIdObject;


    private final String FACE_DATA = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAIAQMAAAD+wSzIAAAABlBMVEX///+/v7+jQ3Y5AAAADklEQVQI12P4AIX8EAgALgAD/aNpbtEAAAAASUVORK5CYII";


    @SneakyThrows
    @Before
    public void setUp() {

        // vc2 definition
        String vc2Type = "MockVerifiableCredential,VerifiableCredential";
        String vc2Context = "https://example.org/Person.json,https://www.w3.org/ns/credentials/v2";
        String vc2Format = "ldp_vc";
        vc2TemplateKey = vc2Type + DELIMITER + vc2Context + DELIMITER + vc2Format;
        vc2TemplateIdObject = new TemplateId(vc2Context, vc2Type, vc2Format);
        vc2 = initTemplate("""
                        {
                            "@context": ["https://www.w3.org/ns/credentials/v2"],
                            "id": "${_id}",
                            "issuer": "${_issuer}",
                            "type": ["VerifiableCredential", "MockVerifiableCredential"],
                            "validFrom": "${validFrom}",
                            "validUntil": "${validUntil}",
                            "credentialSubject": {
                                "gender": "${gender}",
                                "postalCode": ${postalCode},
                                "fullName": "${fullName}",
                                "dateOfBirth": "${dateOfBirth}",
                                "province": "${province}",
                                "phone": "${phone}",
                                "addressLine1": ${addressLine1},
                                "region": "${region}",
                                "vcVer": "${vcVer}",
                                "UIN": ${UIN},
                                "email": "${email}",
                                "face": "${face}"
                            }
                        }
                """,
                vc2Type, vc2Context, vc2Format, "did:example:issuer2", "appId2", "refId2", "EdDSA", "$.phone"
        );

        // vc3 definition - with quotes fixed for string template variables
        String vc3Type = "MockVerifiableCredential,VerifiableCredential";
        String vc3Context = "https://vharsh.github.io/DID/mock-context.json,https://www.w3.org/2018/credentials/v1";
        String vc3Format = "ldp_vc";
        vc3TemplateKey = vc3Type + DELIMITER + vc3Context + DELIMITER + vc3Format;
        vc3TemplateIdObject = new TemplateId(vc3Context, vc3Type, vc3Format);
        vc3 = initTemplate("""
                        {
                            "@context": ["https://www.w3.org/2018/credentials/v1", "https://vharsh.github.io/DID/mock-context.json"],
                            "id": "${_id}",
                            "issuer": "${_issuer}",
                            "type": ["VerifiableCredential", "MockVerifiableCredential"],
                            "issuanceDate": "${validFrom}",
                            "expirationDate": "${validUntil}",
                            "credentialSubject": {
                                "gender": "${gender}",
                                "postalCode": ${postalCode},
                                "fullName": "${fullName}",
                                "dateOfBirth": "${dateOfBirth}",
                                "province": "${province}",
                                "phone": "${phone}",
                                "addressLine1": ${addressLine1},
                                "region": "${region}",
                                "vcVer": "${vcVer}",
                                "UIN": ${UIN},
                                "email": "${email}",
                                "face": "${face}"
                            }
                        }
                """,
                vc3Type, vc3Context, vc3Format, "did:example:issuer3", "appId3", "refId3", "EdDSA", null
        );


        // vc4 definition (template string is null)
        String vc4Type = "TestVerifiableCredential,VerifiableCredential";
        String vc4Context = "https://vharsh.github.io/DID/mock-context.json,https://www.w3.org/2018/credentials/v1";
        String vc4Format = "ldp_vc";
        vc4TemplateKey = vc4Type + DELIMITER + vc4Context + DELIMITER + vc4Format;
        vc4TemplateIdObject = new TemplateId(vc4Context, vc4Type, vc4Format);
        vc4 = initTemplate(null,
                vc4Type, vc4Context, vc4Format, "did:example:issuer4", "appId4", "refId4", "RSA", null
        );


        ReflectionTestUtils.setField(formatter, "defaultExpiryDuration", "P730d");
        ReflectionTestUtils.setField(formatter, "idPrefix", "uurn:uuid:");


        when(credentialConfigRepository.findById(vc2TemplateIdObject)).thenReturn(Optional.of(vc2));

        when(credentialConfigRepository.findById(Mockito.argThat(arg -> !arg.equals(vc2TemplateIdObject))))
                .thenReturn(Optional.empty());



        formatter.initialize(); // Initializes VelocityEngine
    }

    private CredentialConfig initTemplate(String template, String type, String context, String format, String didUrl, String keyManagerAppId, String keyManagerRefId, String signatureAlgo, String sdClaim) {
        CredentialConfig t = new CredentialConfig();
        if(template != null) {
            template = Base64.getEncoder().encodeToString(template.getBytes());
        }

        t.setVcTemplate(template);
        t.setCredentialType(type);
        t.setContext(context);
        t.setCredentialFormat(format); // Make sure CredentialConfig has this field and setter
        t.setDidUrl(didUrl);
        t.setKeyManagerAppId(keyManagerAppId);
        t.setKeyManagerRefId(keyManagerRefId);
        t.setSignatureAlgo(signatureAlgo);
        t.setSdClaim(sdClaim);
        return t;
    }

    @SneakyThrows
    @Test
    public void testTemplating() {


        JSONObject ret = new JSONObject();
        ret.put("vcVer", "VC-V1");
        ret.put("fullName", "Amit Developer");
        ret.put("validFrom", "01/01/2022"); // Format as per Constants.UTC_DATETIME_PATTERN if directly used by formatter
        ret.put("validUntil", "02/02/2122"); // Format as per Constants.UTC_DATETIME_PATTERN
        ret.put("gender", "female");
        ret.put("dateOfBirth", "01/01/2000");
        ret.put("email", "amit@fakemail.com");
        ret.put("UIN", 123456L); // Use Long for UIN
        ret.put("phone", "1234567890");
        ret.put("addressLine1", List.of("1", "Fake building", "Fake Area", "Fake City", "Near Fake Landmark"));
        ret.put("province", "Fake Area");
        ret.put("region", "FakeRegion");
        ret.put("postalCode", 123); // Number
        ret.put("face", FACE_DATA);


        Map<String, Object> templateMap = Map.of(
                Constants.TEMPLATE_NAME, vc2TemplateKey,
                Constants.ISSUER_URI, "https://example.com/fake-issuer"
        );

        String actualJSONString = formatter.format(ret, templateMap);
        assertNotNull(actualJSONString);
        JSONObject actualJsonObj = new JSONObject(actualJSONString);


        assertTrue(actualJsonObj.has("id"));
        assertTrue(actualJsonObj.getString("id").startsWith("uurn:uuid:")); // From idPrefix logic
        String idValue = actualJsonObj.getString("id"); // Capture before removing if needed for expected



        String expectedJsonPattern = """
                {
                    "@context": ["https://www.w3.org/ns/credentials/v2"],
                    "id": "%s",
                    "issuer": "https://example.com/fake-issuer",
                    "type": ["VerifiableCredential", "MockVerifiableCredential"],
                    "validFrom": "01/01/2022",
                    "validUntil": "02/02/2122",
                    "credentialSubject": {
                        "gender": "female",
                        "postalCode": 123,
                        "fullName": "Amit Developer",
                        "dateOfBirth": "01/01/2000",
                        "province": "Fake Area",
                        "phone": "1234567890",
                        "addressLine1": ["1", "Fake building", "Fake Area", "Fake City", "Near Fake Landmark"],
                        "region": "FakeRegion",
                        "vcVer": "VC-V1",
                        "UIN": 123456,
                        "email": "amit@fakemail.com",
                        "face": "%s"
                    }
                }
                """.formatted(idValue, FACE_DATA); // Use the captured dynamic ID

        JsonAssertions.assertThatJson(actualJSONString)
                .isEqualTo(expectedJsonPattern);
    }

    @SneakyThrows
    @Test
    public void testTemplating_templateStringIsNull_thenFailWithCertifyException() {
        // Mock repository to return vc4 (which has vcTemplate = null) for its TemplateId
        when(credentialConfigRepository.findById(vc4TemplateIdObject)).thenReturn(Optional.of(vc4));

        JSONObject ret = new JSONObject(); // Minimal input
        ret.put("someKey", "someValue");


        Map<String, Object> templateMap = Map.of(
                Constants.TEMPLATE_NAME, vc4TemplateKey,
                Constants.ISSUER_URI, "https://example.com/fake-issuer"
        );
        // formatter.format calls getCachedCredentialConfig().getVcTemplate(). If null, it throws.
        CertifyException exception = assertThrows(CertifyException.class, () -> formatter.format(ret, templateMap));
        Assert.assertEquals(ErrorConstants.EXPECTED_TEMPLATE_NOT_FOUND, exception.getErrorCode());
    }

    @Ignore("This test requires a running local server and is for manual/integration testing")
    @Test
    public void testTemplating_localOnly() { /* ... unchanged ... */ }

    @Test
    public void getTemplate_ValidKey_ReturnsTemplateString() {
        // formatter.getTemplate uses findByCredentialTypeAndContext
        String type = "MockVerifiableCredential,VerifiableCredential";
        String context = "https://example.org/Person.json,https://www.w3.org/ns/credentials/v2"; // context part of vc2
        String keyForGetTemplate = type + DELIMITER + context; // Key format for getTemplate() method

        when(credentialConfigRepository.findByCredentialTypeAndContext(type, context))
                .thenReturn(Optional.of(vc2));

        String template = formatter.getTemplate(keyForGetTemplate);
        Assert.assertNotNull(template);
        Assert.assertEquals(vc2.getVcTemplate(), template);
    }

    @Test
    public void getTemplate_InvalidKeyFormat_ReturnsNull() {
        // Key format doesn't contain DELIMITER, or has other issues specific to getTemplate's parsing
        String key = "InvalidKeyWithoutDelimiter";
        String template = formatter.getTemplate(key); // getTemplate has its own parsing
        Assert.assertNull(template);

        String keyWithWrongDelimiter = "Type;Context"; // formatter.getTemplate uses ":"
        template = formatter.getTemplate(keyWithWrongDelimiter);
        Assert.assertNull(template); // This will also result in null as DELIMITER ":" is not found
    }


    @Test
    public void getTemplate_ConfigFoundButTemplateStringIsNull_ReturnsNull() {

        String vc4TypeForGetTemplate = "TestVerifiableCredential,VerifiableCredential";

        String vc4ContextForGetTemplate = "https://vharsh.github.io/DID/mock-context.json,https://www.w3.org/2018/credentials/v1" + DELIMITER + "ldp_vc";
        String keyForVc4GetTemplate = vc4TypeForGetTemplate + DELIMITER + vc4ContextForGetTemplate;


        when(credentialConfigRepository.findByCredentialTypeAndContext(vc4TypeForGetTemplate, vc4ContextForGetTemplate))
                .thenReturn(Optional.of(vc4)); // vc4.getVcTemplate() is null

        String template = formatter.getTemplate(keyForVc4GetTemplate);
        Assert.assertNull(template);
    }


    @Test
    public void testGetProofAlgorithm() {
        // Uses vc2 by default from setUp's findById mock
        String expected = vc2.getSignatureAlgo();
        Assert.assertEquals(expected, formatter.getProofAlgorithm(vc2TemplateKey));
    }

    @Test
    public void testGetDidUrl() {
        // Uses vc2 by default
        String expected = vc2.getDidUrl();
        Assert.assertEquals(expected, formatter.getDidUrl(vc2TemplateKey));
    }

    @Test
    public void testGetRefID() {
        // Uses vc2 by default
        String expected = vc2.getKeyManagerRefId();
        Assert.assertEquals(expected, formatter.getRefID(vc2TemplateKey));
    }

    @Test
    public void testGetAppID() {
        // Uses vc2 by default
        String expected = vc2.getKeyManagerAppId();
        Assert.assertEquals(expected, formatter.getAppID(vc2TemplateKey));
    }

    @Test
    public void testGetSelectiveDisclosureInfo() {
        // Uses vc2 by default
        List<String> expectedList = Arrays.asList(vc2.getSdClaim().split(","));
        Assert.assertEquals(expectedList, formatter.getSelectiveDisclosureInfo(vc2TemplateKey));
    }

    @Test
    public void testFormat_AddsDefaultExpiryWhenMissing() {
        // Uses vc2 by default from setUp's findById mock
        JSONObject valueMap = new JSONObject();
        valueMap.put("vcVer", "VC-V1");
        valueMap.put("fullName", "Test User");
        valueMap.put("UIN", 123456L);
        valueMap.put("postalCode", 123);
        // Minimal fields for vc2, validFrom/validUntil are missing from input
        valueMap.put("gender", "N/A");
        valueMap.put("dateOfBirth", "N/A");
        valueMap.put("email", "test@example.com");
        valueMap.put("phone", "0000000000");
        valueMap.put("addressLine1", new JSONArray());
        valueMap.put("province", "N/A");
        valueMap.put("region", "N/A");
        valueMap.put("face", "N/A");


        Map<String, Object> templateSettings = Map.of(
                Constants.TEMPLATE_NAME, vc2TemplateKey,
                Constants.ISSUER_URI, "https://example.com/fake-issuer"
        );

        String result = formatter.format(valueMap, templateSettings);
        assertNotNull(result);

        JSONObject jsonResult = new JSONObject(result);
        assertTrue(jsonResult.has(VCDM2Constants.VALID_FROM)); // Check using constant
        assertTrue(jsonResult.has(VCDM2Constants.VALID_UNITL)); // Check using constant
        assertNotNull(jsonResult.getString(VCDM2Constants.VALID_FROM));
        assertNotNull(jsonResult.getString(VCDM2Constants.VALID_UNITL));
    }

    @Test
    public void testFormat_AddsIdPrefixIfIdNotInTemplate() {


        JSONObject valueMap = new JSONObject();
        valueMap.put("vcVer", "VC-V1");
        valueMap.put("fullName", "Test User");
        valueMap.put("UIN", 123456L);
        valueMap.put("postalCode", 123);
        valueMap.put("gender", "N/A");
        valueMap.put("dateOfBirth", "N/A");
        valueMap.put("email", "test@example.com");
        valueMap.put("phone", "0000000000");
        valueMap.put("addressLine1", new JSONArray());
        valueMap.put("province", "N/A");
        valueMap.put("region", "N/A");
        valueMap.put("face", "N/A");



        Map<String, Object> templateSettings = Map.of(
                Constants.TEMPLATE_NAME, vc2TemplateKey,
                Constants.ISSUER_URI, "https://example.com/fake-issuer"
        );

        String result = formatter.format(valueMap, templateSettings);
        JSONObject jsonResult = new JSONObject(result);
        assertTrue(jsonResult.has("id"));
        assertTrue(jsonResult.getString("id").startsWith("uurn:uuid:")); // Verifies idPrefix logic

    }

    @Test
    @SneakyThrows
    public void testFormat_WithMapInput_HappyPath() {
        // Mock for vc3
        when(credentialConfigRepository.findById(vc3TemplateIdObject)).thenReturn(Optional.of(vc3));

        Map<String, Object> templateInput = new HashMap<>();
        templateInput.put(Constants.TEMPLATE_NAME, vc3TemplateKey);
        templateInput.put(Constants.ISSUER_URI, "https://example.com/fake-issuer");
        templateInput.put("vcVer", "VC-V3");
        templateInput.put("fullName", "Test User Three"); // String, template vc3 now quotes it.
        templateInput.put("UIN", 789012L);
        templateInput.put("postalCode", 789);
        templateInput.put("gender", "other"); // String, template vc3 quotes it.
        templateInput.put("dateOfBirth", "03/03/1993");
        templateInput.put("email", "vc3@example.com");
        templateInput.put("phone", "3333333333");
        templateInput.put("addressLine1", List.of("VC3 Addr", "Line 2"));
        templateInput.put("province", "VC3 Province"); // String, template vc3 quotes it.
        templateInput.put("region", "VC3 Region");   // String, template vc3 quotes it.
        templateInput.put("face", "data:image/gif;base64,vc3facedata");
        templateInput.put(VCDM2Constants.VALID_FROM, "2023-03-01T00:00:00Z"); // Explicitly provide
        templateInput.put(VCDM2Constants.VALID_UNITL, "2025-03-01T00:00:00Z"); // Explicitly provide


        String result = formatter.format(templateInput); // Uses the overloaded format(Map)
        assertNotNull(result);

        JSONObject actualJsonObj = new JSONObject(result);
        assertTrue(actualJsonObj.has("id"));
        assertTrue(actualJsonObj.getString("id").startsWith("uurn:uuid:"));
        Assert.assertEquals("Test User Three", actualJsonObj.getJSONObject("credentialSubject").getString("fullName"));
        Assert.assertEquals(789012L, actualJsonObj.getJSONObject("credentialSubject").getLong("UIN"));
        Assert.assertEquals("https://example.com/fake-issuer", actualJsonObj.getString("issuer"));
    }
}