package io.mosip.certify.vcformatters;

import java.time.format.DateTimeFormatter;
import java.util.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.exception.RenderingTemplateException;
import io.mosip.certify.core.spi.RenderingTemplateService;
import org.apache.velocity.app.VelocityEngine;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Assert;
import static org.junit.Assert.assertThrows;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;


import junit.framework.TestCase;
import lombok.SneakyThrows;
import net.javacrumbs.jsonunit.assertj.JsonAssertions;



@Service
@RunWith(MockitoJUnitRunner.class)
public class VelocityTemplatingEngineImplTest extends TestCase {
    @InjectMocks
    private VelocityTemplatingEngineImpl formatter;
    @Mock
    CredentialConfigRepository credentialConfigRepository;

    private CredentialConfig vc1;
    private CredentialConfig vc2;
    private CredentialConfig vc3;
    private CredentialConfig vc4;

    @SneakyThrows
    @Before
    public void setUp() {
        vc1 = initTemplate("""
                {
                    "@context": [
                    "https://www.w3.org/2018/credentials/v1"]
                    "issuer": "${_issuer}",
                    "type": ["VerifiableCredential", "MockVerifiableCredential"],
                    "issuanceDate": "${validFrom}",
                    "expirationDate": "${validUntil}",
                    "credentialSubject": {
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
                "MockVerifiableCredential,VerifiableCredential",
                "https://schema.org,https://www.w3.org/2018/credentials/v1",
                "ldp_vc",
                "did:example:issuer",
                "appId",
                "refId",
                "EdDSA",
                "$.email,$.phone"
        );
        vc2 = initTemplate("""
                        {
                            "@context": [
                                    "https://www.w3.org/ns/credentials/v2"],
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
                "MockVerifiableCredential,VerifiableCredential",
                "https://example.org/Person.json,https://www.w3.org/ns/credentials/v2",
                "ldp_vc",
                "did:example:issuer",
                "appId",
                "refId",
                "EdDSA",
                "$.email,$.phone"

        );
        vc3 = initTemplate("""
                        {
                            "@context": [
                            "https://www.w3.org/2018/credentials/v1",
                            "https://vharsh.github.io/DID/mock-context.json"],
                            "issuer": "${_issuer}",
                            "type": ["VerifiableCredential", "MockVerifiableCredential"],
                            "issuanceDate": "${validFrom}",
                            "expirationDate": "${validUntil}",
                            "credentialSubject": {
                                "gender": ${gender},
                                "postalCode": ${postalCode},
                                "fullName": ${fullName},
                                "dateOfBirth": "${dateOfBirth}",
                                "province": ${province},
                                "phone": "${phone}",
                                "addressLine1": ${addressLine1},
                                "region": ${region},
                                "vcVer": "${vcVer}",
                                "UIN": ${UIN},
                                "email": "${email}",
                                "face": "${face}"
                            }
                        }
                """,
                "MockVerifiableCredential,VerifiableCredential",
                "https://vharsh.github.io/DID/mock-context.json,https://www.w3.org/2018/credentials/v1",
                "ldp_vc",
                "did:example:issuer",
                "appId",
                "refId",
                "EdDSA",
                "$.email,$.phone"
        );
        vc4 = initTemplate(null,
                "TestVerifiableCredential,VerifiableCredential",
                "https://vharsh.github.io/DID/mock-context.json,https://www.w3.org/2018/credentials/v1",
                "ldp_vc",
                "did:example:issuer",
                "appId",
                "refId",
                "EdDSA",
                "$.email,$.phone"
        );

        ObjectMapper objectMapper = new ObjectMapper();
        ReflectionTestUtils.setField(formatter, "objectMapper", objectMapper);
        ReflectionTestUtils.setField(formatter, "defaultExpiryDuration", "P730d");
        ReflectionTestUtils.setField(formatter, "idPrefix", "uurn:uuid");
        //when(templateRepository.findByCredentialTypeAndContext("MockVerifiableCredential,VerifiableCredential", "https://schema.org,https://www.w3.org/2018/credentials/v1")).thenReturn(Optional.of(vc1));
        when(credentialConfigRepository.findByCredentialTypeAndContext("MockVerifiableCredential,VerifiableCredential", "https://example.org/Person.json,https://www.w3.org/ns/credentials/v2")).thenReturn(Optional.of(vc2));
        when(credentialConfigRepository.findAll()).thenReturn(Collections.singletonList(vc2));
        formatter.initialize();
    }

    private CredentialConfig initTemplate(String template, String type, String context, String format, String didUrl, String keyManagerAppId, String keyManagerRefId, String signatureAlgo, String sdClaim) {
        CredentialConfig t = new CredentialConfig();
        t.setVcTemplate(template);
        t.setCredentialType(type);
        t.setContext(context);
        t.setCredentialFormat(format);
        t.setDidUrl(didUrl);
        t.setKeyManagerAppId(keyManagerAppId);
        t.setKeyManagerRefId(keyManagerRefId);
        t.setSignatureAlgo(signatureAlgo);
        t.setSdClaim(sdClaim);
        return t;
    }


    private CredentialConfig initTemplate(String template, String type, String context) {
        CredentialConfig t = new CredentialConfig();
        t.setVcTemplate(template);
        t.setCredentialType(type);
        return t;
    }

    @SneakyThrows
    @Test
//    @Ignore
    public void testTemplating() {
        JSONObject ret = new JSONObject();
        ret.put("vcVer", "VC-V1");
        // ret.put("issuer", "https://example.com/fake-issuer");
        ret.put("fullName", "Amit Developer");
        ret.put("validFrom", "01/01/2022");
        ret.put("validUntil", "02/02/2122");
        ret.put("gender", "female");
        ret.put("dateOfBirth", "01/01/2022");
        ret.put("email", "amit@fakemail.com");
        ret.put("UIN", 123456);
        ret.put("phone", "1234567890");
        // both of the below work
        ret.put("addressLine1", List.of("1", "Fake building", "Fake Area", "Fake City", "Near Fake Landmark"));
        // ret.put("addressLine1", new String[]{"1", "Fake building", "Fake Area", "Fake City", "Near Fake Landmark"});
        ret.put("province", "Fake Area");
        ret.put("region", "FakeRegion");
        ret.put("postalCode", "123");
        ret.put("face", "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAIAQMAAAD+wSzIAAAABlBMVEX///+/v7+jQ3Y5AAAADklEQVQI12P4AIX8EAgALgAD/aNpbtEAAAAASUVORK5CYII");
        Map<String, Object> templateMap = Map.of("templateName", "MockVerifiableCredential,VerifiableCredential:https://example.org/Person.json,https://www.w3.org/ns/credentials/v2:ldp_vc",
                "issuerURI", "https://example.com/fake-issuer");
        String actualJSON = formatter.format(ret, templateMap);
//        String expectedJSON = """
//                {"credentialSubject":{"face":"data:image\\/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAIAQMAAAD+wSzIAAAABlBMVEX\\/\\/\\/+\\/v7+jQ3Y5AAAADklEQVQI12P4AIX8EAgALgAD\\/aNpbtEAAAAASUVORK5CYII","gender":"female","province":"Fake Area","phone":"1234567890","postalCode":123,"fullName":"Amit Developer","addressLine1":["1","Fake building","Fake Area","Fake City","Near Fake Landmark"],"dateOfBirth":"01\\/01\\/2022","vcVer":"VC-V1","UIN":123456,"region":"FakeRegion","email":"amit@fakemail.com"},"validUntil":"02\\/02\\/2122","validFrom":"01\\/01\\/2022","type":["VerifiableCredential","MockVerifiableCredential"],"@context":["https:\\/\\/www.w3.org\\/ns\\/credentials\\/v2"],"issuer":"https:\\/\\/example.com\\/fake-issuer"}
//                """;
//        JsonAssertions.assertThatJson(actualJSON).isEqualTo(expectedJSON);
        assertNotNull(actualJSON);
    }

    @SneakyThrows
    @Test
//    @Ignore
    public void testTemplating_templateNotFound_thenFail() {
        when(credentialConfigRepository.findAll()).thenReturn(Collections.singletonList(vc4));
        formatter.initialize();
        JSONObject ret = new JSONObject();
        ret.put("vcVer", "VC-V1");
        // ret.put("issuer", "https://example.com/fake-issuer");
        ret.put("fullName", "Amit Developer");
        ret.put("validFrom", "01/01/2022");
        ret.put("validUntil", "02/02/2122");
        ret.put("gender", "female");
        ret.put("dateOfBirth", "01/01/2022");
        ret.put("email", "amit@fakemail.com");
        ret.put("UIN", 123456);
        ret.put("phone", "1234567890");
        // both of the below work
        ret.put("addressLine1", List.of("1", "Fake building", "Fake Area", "Fake City", "Near Fake Landmark"));
        // ret.put("addressLine1", new String[]{"1", "Fake building", "Fake Area", "Fake City", "Near Fake Landmark"});
        ret.put("province", "Fake Area");
        ret.put("region", "FakeRegion");
        ret.put("postalCode", "123");
        ret.put("face", "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAIAQMAAAD+wSzIAAAABlBMVEX///+/v7+jQ3Y5AAAADklEQVQI12P4AIX8EAgALgAD/aNpbtEAAAAASUVORK5CYII");
        Map<String, Object> templateMap = Map.of("templateName", "TestVerifiableCredential,VerifiableCredential:https://vharsh.github.io/DID/mock-context.json,https://www.w3.org/2018/credentials/v1:ldp_vc",
                "issuerURI", "https://example.com/fake-issuer");
        assertThrows(CertifyException.class, () -> formatter.format(ret, templateMap));
    }

    @Ignore
    @Test
    public void testTemplating_localOnly() {
        // This test is written to rapidly test out changes against a hosted mock-identity system
        RestTemplate r = new RestTemplate();
        Map<String, Object> x = r.getForObject("http://localhost:8082/v1/mock-identity-system/identity/12345678",
                HashMap.class);
        Map<String, Object> res = (Map<String, Object>) x.get("response");
        JSONObject ret = new JSONObject(res);

        Map<String, Object> templateMap = Map.of("templateName", "MockVerifiableCredential,VerifiableCredential:https://vharsh.github.io/DID/mock-context.json,https://www.w3.org/2018/credentials/v1",
                "issuerURI", "https://example.com/fake-issuer");
        String actualJSON = formatter.format(ret, templateMap);
        try {
            JSONObject unused = new JSONObject(actualJSON);
        } catch (JSONException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void getTemplateNameWithValidKey_thenPass() {
        String key = "MockVerifiableCredential,VerifiableCredential:https://example.org/Person.json,https://www.w3.org/ns/credentials/v2";
        String template = formatter.getTemplate(key);
        Assert.assertNotNull(template);
        Assert.assertEquals(vc2.getVcTemplate(), template);
    }

    @Test
    public void getTemplateNameWithInvalidKey_thenFail() {
        String key = "TestVerifiableCredential,VerifiableCredential;example.org/Person.json,www.w3.org/ns/credentials/v2";
        String template = formatter.getTemplate(key);
        Assert.assertNull(template);
    }

    @Test
    public void getTemplateNameWithNullTemplate_thenFail() {
        String key = "TestVerifiableCredential,VerifiableCredential:https://vharsh.github.io/DID/mock-context.json,https://www.w3.org/2018/credentials/v1";
        String template = formatter.getTemplate(key);
        Assert.assertNull(template);
    }

    @Test
    public void testGetProofAlgorithm() {
        String templateName = "MockVerifiableCredential,VerifiableCredential:https://example.org/Person.json,https://www.w3.org/ns/credentials/v2:ldp_vc";
        String expected = vc2.getSignatureAlgo();
        Assert.assertEquals(expected, formatter.getProofAlgorithm(templateName));
    }

    @Test
    public void testGetDidUrl() {
        String templateName = "MockVerifiableCredential,VerifiableCredential:https://example.org/Person.json,https://www.w3.org/ns/credentials/v2:ldp_vc";
        String expected = vc2.getDidUrl();
        Assert.assertEquals(expected, formatter.getDidUrl(templateName));
    }

    @Test
    public void testGetRefID() {
        String templateName = "MockVerifiableCredential,VerifiableCredential:https://example.org/Person.json,https://www.w3.org/ns/credentials/v2:ldp_vc";
        String expected = vc2.getKeyManagerRefId();
        Assert.assertEquals(expected, formatter.getRefID(templateName));
    }

    @Test
    public void testGetAppID() {
        String templateName = "MockVerifiableCredential,VerifiableCredential:https://example.org/Person.json,https://www.w3.org/ns/credentials/v2:ldp_vc";
        String expected = vc2.getKeyManagerAppId();
        Assert.assertEquals(expected, formatter.getAppID(templateName));
    }

    @Test
    public void testGetSelectiveDisclosureInfo() {
        String templateName = "MockVerifiableCredential,VerifiableCredential:https://example.org/Person.json,https://www.w3.org/ns/credentials/v2:ldp_vc";
        List<String> expectedList = Arrays.asList(vc2.getSdClaim().split(","));
        Assert.assertEquals(expectedList, formatter.getSelectiveDisclosureInfo(templateName));
    }

    @Test
    public void testFormat_AddsDefaultExpiryWhenMissing() {
        JSONObject valueMap = new JSONObject();
        // Add minimal required fields for the template to generate valid JSON
        valueMap.put("vcVer", "VC-V1");
        valueMap.put("fullName", "Test User");
        valueMap.put("UIN", 123456);
        valueMap.put("postalCode", 123);
        valueMap.put("gender", "");
        valueMap.put("dateOfBirth", "");
        valueMap.put("email", "");
        valueMap.put("phone", "");
        valueMap.put("addressLine1", new JSONArray()); // Empty array
        valueMap.put("province", "");
        valueMap.put("region", "");
        valueMap.put("face", "");

        Map<String, Object> templateSettings = Map.of(
                "templateName", "MockVerifiableCredential,VerifiableCredential:https://example.org/Person.json,https://www.w3.org/ns/credentials/v2:ldp_vc",
                "issuerURI", "https://example.com/fake-issuer"
        );

        String result = formatter.format(valueMap, templateSettings);
        assertNotNull(result);

        // Verify default expiry is added
        JSONObject jsonResult = new JSONObject(result);
        assertTrue(jsonResult.has("validFrom"));
        assertTrue(jsonResult.has("validUntil"));
    }

    @Test
    public void testFormat_AddsIdPrefix() {
        JSONObject valueMap = new JSONObject();
        valueMap.put("vcVer", "VC-V1");
        valueMap.put("fullName", "Test User");
        valueMap.put("UIN", 123456);
        valueMap.put("postalCode", 123);
        valueMap.put("gender", "");
        valueMap.put("dateOfBirth", "");
        valueMap.put("email", "");
        valueMap.put("phone", "");
        valueMap.put("addressLine1", new JSONArray()); // Empty array
        valueMap.put("province", "");
        valueMap.put("region", "");
        valueMap.put("face", "");
        Map<String, Object> templateSettings = Map.of(
                "templateName", "MockVerifiableCredential,VerifiableCredential:https://example.org/Person.json,https://www.w3.org/ns/credentials/v2:ldp_vc",
                "issuerURI", "https://example.com/fake-issuer"
        );

        String result = formatter.format(valueMap, templateSettings);
        JSONObject jsonResult = new JSONObject(result);
        assertTrue(jsonResult.has("id"));
    }

    @Test
    public void testFormat_WithMapInput_HappyPath() {
        when(credentialConfigRepository.findAll()).thenReturn(Collections.singletonList(vc3));
        formatter.initialize();
        Map<String, Object> templateInput = new HashMap<>();
        templateInput.put(Constants.TEMPLATE_NAME, "MockVerifiableCredential,VerifiableCredential:https://vharsh.github.io/DID/mock-context.json,https://www.w3.org/2018/credentials/v1:ldp_vc");
        templateInput.put(Constants.ISSUER_URI, "https://example.com/fake-issuer");
        templateInput.put("vcVer", "VC-V1");
        templateInput.put("fullName", "test");
        templateInput.put("UIN", 123456);
        templateInput.put("postalCode", "123");
        templateInput.put("gender", "female");
        templateInput.put("dateOfBirth", "01/01/2022");
        templateInput.put("email", "amit@fakemail.com");
        templateInput.put("phone", "1234567890");
        templateInput.put("addressLine1", List.of("1", "Fake building"));
        templateInput.put("province", "Fake Area");
        templateInput.put("region", "FakeRegion");
        templateInput.put("face", "data:image/png;base64,iVBORw0KG...");

        String result = formatter.format(templateInput);
        assertNotNull(result);
        assertTrue(result.contains("test"));
        assertTrue(result.contains("123456"));
    }
}