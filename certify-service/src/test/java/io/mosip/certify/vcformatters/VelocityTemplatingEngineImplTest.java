package io.mosip.certify.vcformatters;

import java.util.*;


import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.constants.VCDMConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.RenderingTemplateException;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Assert;

import static io.mosip.certify.core.constants.Constants.DELIMITER;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.core.spi.RenderingTemplateService;

import lombok.SneakyThrows;


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

    private String vc3TemplateKey;

    private String vc4TemplateKey;


    private final String FACE_DATA = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAIAQMAAAD+wSzIAAAABlBMVEX///+/v7+jQ3Y5AAAADklEQVQI12P4AIX8EAgALgAD/aNpbtEAAAAASUVORK5CYII";


    @SneakyThrows
    @Before
    public void setUp() {

        // vc2 definition
        String vc2Type = "MockVerifiableCredential,VerifiableCredential";
        String vc2Context = "https://example.org/Person.json,https://www.w3.org/ns/credentials/v2";
        String vc2Format = "ldp_vc";
        vc2TemplateKey = vc2Type + DELIMITER + vc2Context + DELIMITER + vc2Format;
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
                vc2Type, vc2Context, vc2Format, "did:example:issuer2", "appId2", "refId2", "EdDSA", "$.phone", "testCryptoSuite"
        );

        // vc3 definition - with quotes fixed for string template variables
        String vc3Type = "MockVerifiableCredential,VerifiableCredential";
        String vc3Context = "https://vharsh.github.io/DID/mock-context.json,https://www.w3.org/2018/credentials/v1";
        String vc3Format = "ldp_vc";
        vc3TemplateKey = vc3Type + DELIMITER + vc3Context + DELIMITER + vc3Format;
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
                vc3Type, vc3Context, vc3Format, "did:example:issuer3", "appId3", "refId3", "EdDSA", null, "testCryptoSuite"
        );


        // vc4 definition (template string is null)
        String vc4Type = "TestVerifiableCredential,VerifiableCredential";
        String vc4Context = "https://vharsh.github.io/DID/mock-context.json,https://www.w3.org/2018/credentials/v1";
        String vc4Format = "ldp_vc";
        vc4TemplateKey = vc4Type + DELIMITER + vc4Context + DELIMITER + vc4Format;
        vc4 = initTemplate(null,
                vc4Type, vc4Context, vc4Format, "did:example:issuer4", "appId4", "refId4", "RSA", null, "testCryptoSuite"
        );


        ReflectionTestUtils.setField(formatter, "objectMapper", new ObjectMapper());
        ReflectionTestUtils.setField(formatter, "defaultExpiryDuration", "P730d");
        ReflectionTestUtils.setField(formatter, "idPrefix", "uurn:uuid:");


        when(credentialConfigRepository.findByCredentialFormatAndCredentialTypeAndContext(vc2Format, vc2Type, vc2Context)).thenReturn(Optional.of(vc2));

        formatter.initialize(); // Initializes VelocityEngine
    }

    private CredentialConfig initTemplate(String template, String type, String context, String format, String didUrl, String keyManagerAppId, String keyManagerRefId, String signatureAlgo, String sdClaim, String signatureCryptoSuite) {
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
        t.setSignatureCryptoSuite(signatureCryptoSuite);
        return t;
    }

    @Ignore("This test requires a running local server and is for manual/integration testing")
    @Test
    public void testTemplating_localOnly() { /* ... unchanged ... */ }


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
    public void testGetSignatureCryptoSuite() {
        // Uses vc2 by default
        String expected = vc2.getSignatureCryptoSuite();
        Assert.assertEquals(expected, formatter.getSignatureCryptoSuite(vc2TemplateKey));
    }

    // ---- folded from VelocityTemplatingEngineImplExtraTest ----

    private final String VC2_URL = VCDM2Constants.URL;
    private final String extraType = "MockType";
    private final String ldpKey = extraType + DELIMITER + VC2_URL + DELIMITER + VCFormats.LDP_VC;

    private String encode(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes());
    }

    private CredentialConfig ldpConfig(String template) {
        CredentialConfig cc = new CredentialConfig();
        cc.setVcTemplate(template == null ? null : encode(template));
        cc.setCredentialType(extraType);
        cc.setContext(VC2_URL);
        cc.setCredentialFormat(VCFormats.LDP_VC);
        cc.setDidUrl("did:example:issuer");
        return cc;
    }

    private void mockLdp(CredentialConfig cc) {
        when(credentialConfigRepository.findByCredentialFormatAndCredentialTypeAndContext(
                VCFormats.LDP_VC, extraType, VC2_URL)).thenReturn(Optional.of(cc));
    }

    @Test
    public void format_basic_setsIssuer() {
        mockLdp(ldpConfig("{\"issuer\":\"${_issuer}\",\"name\":\"${name}\"}"));
        Map<String, Object> params = new HashMap<>();
        params.put(Constants.TEMPLATE_NAME, ldpKey);
        params.put(Constants.DID_URL, "did:example:issuer");
        params.put("name", "Alice");

        String result = formatter.format(params);
        JSONObject json = new JSONObject(result);
        assertEquals("did:example:issuer", json.getString("issuer"));
        assertEquals("Alice", json.getString("name"));
    }

    @Test
    public void format_withCredentialId_setsId() {
        mockLdp(ldpConfig("{\"issuer\":\"${_issuer}\"}"));
        Map<String, Object> params = new HashMap<>();
        params.put(Constants.TEMPLATE_NAME, ldpKey);
        params.put(Constants.DID_URL, "did:example:issuer");
        params.put(VCDMConstants.CREDENTIAL_ID, "urn:uuid:abc");

        JSONObject json = new JSONObject(formatter.format(params));
        assertEquals("urn:uuid:abc", json.getString(VCDMConstants.ID));
    }

    @Test
    public void format_withCredentialStatus_whenVcdm2Url() {
        mockLdp(ldpConfig("{\"issuer\":\"${_issuer}\"}"));
        Map<String, Object> params = new HashMap<>();
        params.put(Constants.TEMPLATE_NAME, ldpKey);
        params.put(Constants.DID_URL, "did:example:issuer");
        Map<String, Object> status = Map.of("type", "BitstringStatusListEntry");
        params.put(VCDM2Constants.CREDENTIAL_STATUS, status);

        JSONObject json = new JSONObject(formatter.format(params));
        assertTrue(json.has(VCDM2Constants.CREDENTIAL_STATUS));
    }

    @Test
    public void format_withVctConfirmationIssuer() {
        mockLdp(ldpConfig("{\"issuer\":\"${_issuer}\"}"));
        Map<String, Object> params = new HashMap<>();
        params.put(Constants.TEMPLATE_NAME, ldpKey);
        params.put(Constants.DID_URL, "did:example:issuer");
        params.put(Constants.VCTYPE, "MyVct");
        params.put(Constants.CONFIRMATION, Map.of("jwk", "x"));
        params.put(Constants.ISSUER, "https://issuer");

        JSONObject json = new JSONObject(formatter.format(params));
        assertEquals("MyVct", json.getString(Constants.VCTYPE));
        assertEquals("https://issuer", json.getString(Constants.ISSUER));
    }

    @Test
    public void format_renderingTemplateMissing_handledGracefully() throws Exception {
        mockLdp(ldpConfig("{\"issuer\":\"${_issuer}\"}"));
        when(renderingTemplateService.getTemplate("render-1"))
                .thenThrow(new RenderingTemplateException("not-found"));
        Map<String, Object> params = new HashMap<>();
        params.put(Constants.TEMPLATE_NAME, ldpKey);
        params.put(Constants.DID_URL, "did:example:issuer");
        params.put(Constants.RENDERING_TEMPLATE_ID, "render-1");

        String result = formatter.format(params);
        assertNotNull(new JSONObject(result));
    }

    @Test
    public void formatQRData_nullSettings_returnsNull() {
        CredentialConfig cc = ldpConfig("{}");
        cc.setQrSettings(null);
        mockLdp(cc);
        Map<String, Object> params = new HashMap<>();
        params.put(Constants.TEMPLATE_NAME, ldpKey);
        assertNull(formatter.formatQRData(params));
    }

    @Test
    public void formatQRData_withSettings_returnsArray() {
        CredentialConfig cc = ldpConfig("{}");
        cc.setQrSettings(List.of(Map.of("key", (Object) "value")));
        mockLdp(cc);
        Map<String, Object> params = new HashMap<>();
        params.put(Constants.TEMPLATE_NAME, ldpKey);
        JSONArray array = formatter.formatQRData(params);
        assertNotNull(array);
        assertEquals(1, array.length());
        assertEquals("value", array.getJSONObject(0).getString("key"));
    }

    @Test
    public void getCachedCredentialConfig_nullKey_throws() {
        assertThrows(CertifyException.class, () -> formatter.getProofAlgorithm(null));
    }

    @Test
    public void getCachedCredentialConfig_noDelimiter_throws() {
        assertThrows(CertifyException.class, () -> formatter.getProofAlgorithm("nodelim"));
    }

    @Test
    public void getCachedCredentialConfig_msoMdocTwoParts() {
        String key = VCFormats.MSO_MDOC + DELIMITER + "org.iso.mdl";
        CredentialConfig cc = new CredentialConfig();
        cc.setSignatureAlgo("ES256");
        when(credentialConfigRepository.findByCredentialFormatAndDocType(VCFormats.MSO_MDOC, "org.iso.mdl"))
                .thenReturn(Optional.of(cc));
        assertEquals("ES256", formatter.getProofAlgorithm(key));
    }

    @Test
    public void getCachedCredentialConfig_sdJwtTwoParts() {
        String key = VCFormats.DC_SD_JWT + DELIMITER + "MyVct";
        CredentialConfig cc = new CredentialConfig();
        cc.setSignatureAlgo("EdDSA");
        when(credentialConfigRepository.findByCredentialFormatAndSdJwtVct(VCFormats.DC_SD_JWT, "MyVct"))
                .thenReturn(Optional.of(cc));
        assertEquals("EdDSA", formatter.getProofAlgorithm(key));
    }

    @Test
    public void getCachedCredentialConfig_undefinedFormatTwoParts_throws() {
        String key = "ldp_vc" + DELIMITER + "something";
        assertThrows(CertifyException.class, () -> formatter.getProofAlgorithm(key));
    }

    @Test
    public void getCachedCredentialConfig_notFound_throws() {
        String key = VCFormats.MSO_MDOC + DELIMITER + "unknown";
        when(credentialConfigRepository.findByCredentialFormatAndDocType(VCFormats.MSO_MDOC, "unknown"))
                .thenReturn(Optional.empty());
        assertThrows(CertifyException.class, () -> formatter.getProofAlgorithm(key));
    }

    @Test
    public void getSelectiveDisclosureInfo_nullSdClaim_returnsEmpty() {
        CredentialConfig cc = ldpConfig("{}");
        cc.setSdClaim(null);
        mockLdp(cc);
        assertTrue(formatter.getSelectiveDisclosureInfo(ldpKey).isEmpty());
    }

    @Test
    public void remainingGetters_delegateToConfig() {
        CredentialConfig cc = ldpConfig("{}");
        cc.setCredentialStatusPurposes(List.of("revocation"));
        cc.setQrSettings(List.of(Map.of("a", (Object) "b")));
        cc.setQrSignatureAlgo("RS256");
        mockLdp(cc);

        assertEquals(List.of("revocation"), formatter.getCredentialStatusPurpose(ldpKey));
        assertEquals(1, formatter.getQRSettings(ldpKey).size());
        assertEquals("RS256", formatter.getQRSignatureAlgo(ldpKey));
    }

//    @Test
//    @SneakyThrows
//    public void testFormat_WithMapInput_HappyPath() {
//        // Mock for vc3
//        String vc3Type = "MockVerifiableCredential,VerifiableCredential";
//        String vc3Context = "https://vharsh.github.io/DID/mock-context.json,https://www.w3.org/2018/credentials/v1";
//        String vc3Format = "ldp_vc";
//        when(credentialConfigRepository.findByCredentialFormatAndCredentialTypeAndContext(vc3Format, vc3Type, vc3Context)).thenReturn(Optional.of(vc3));
//
//        Map<String, Object> templateInput = new HashMap<>();
//        templateInput.put(Constants.TEMPLATE_NAME, vc3TemplateKey);
//        templateInput.put(Constants.DID_URL, "https://example.com/fake-issuer");
//        templateInput.put("vcVer", "VC-V3");
//        templateInput.put("fullName", "Test User Three"); // String, template vc3 now quotes it.
//        templateInput.put("UIN", 789012L);
//        templateInput.put("postalCode", 789);
//        templateInput.put("gender", "other"); // String, template vc3 quotes it.
//        templateInput.put("dateOfBirth", "03/03/1993");
//        templateInput.put("email", "vc3@example.com");
//        templateInput.put("phone", "3333333333");
//        templateInput.put("addressLine1", List.of("VC3 Addr", "Line 2"));
//        templateInput.put("province", "VC3 Province"); // String, template vc3 quotes it.
//        templateInput.put("region", "VC3 Region");   // String, template vc3 quotes it.
//        templateInput.put("face", "data:image/gif;base64,vc3facedata");
//        templateInput.put(VCDM2Constants.VALID_FROM, "2023-03-01T00:00:00Z"); // Explicitly provide
//        templateInput.put(VCDM2Constants.VALID_UNTIL, "2025-03-01T00:00:00Z"); // Explicitly provide
//        templateInput.put(VCDMConstants.CREDENTIAL_ID, "uurn:uuid:");
//
//
//        String result = formatter.format(templateInput, new HashMap<>()); // Uses the overloaded format(Map)
//        assertNotNull(result);
//
//        JSONObject actualJsonObj = new JSONObject(result);
//        assertTrue(actualJsonObj.has("id"));
//        assertTrue(actualJsonObj.getString("id").startsWith("uurn:uuid:"));
//        Assert.assertEquals("Test User Three", actualJsonObj.getJSONObject("credentialSubject").getString("fullName"));
//        Assert.assertEquals(789012L, actualJsonObj.getJSONObject("credentialSubject").getLong("UIN"));
//        Assert.assertEquals("https://example.com/fake-issuer", actualJsonObj.getString("issuer"));
//    }
}