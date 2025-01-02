package io.mosip.certify.vcformatters;

import io.mosip.certify.entity.CredentialTemplate;
import io.mosip.certify.repository.CredentialTemplateRepository;
import junit.framework.TestCase;
import lombok.SneakyThrows;
import net.javacrumbs.jsonunit.assertj.JsonAssertions;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.*;

import static org.mockito.Mockito.when;

@Service
@RunWith(MockitoJUnitRunner.class)
public class VelocityTemplatingEngineImplTest extends TestCase {
    @InjectMocks
    private VelocityTemplatingEngineImpl formatter;
    @Mock
    CredentialTemplateRepository credentialTemplateRepository;

    @SneakyThrows
    @Before
    public void setUp() {
        CredentialTemplate vc1 = initTemplate("""
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
                "https://schema.org,https://www.w3.org/2018/credentials/v1");
        CredentialTemplate vc2 = initTemplate("""
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
                "https://example.org/Person.json,https://www.w3.org/ns/credentials/v2"
        );
        CredentialTemplate vc3 = initTemplate("""
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
                "https://vharsh.github.io/DID/mock-context.json,https://www.w3.org/2018/credentials/v1"
        );
        //when(templateRepository.findByCredentialTypeAndContext("MockVerifiableCredential,VerifiableCredential", "https://schema.org,https://www.w3.org/2018/credentials/v1")).thenReturn(Optional.of(vc1));
        when(credentialTemplateRepository.findByCredentialTypeAndContext("MockVerifiableCredential,VerifiableCredential", "https://example.org/Person.json,https://www.w3.org/ns/credentials/v2")).thenReturn(Optional.of(vc2));
        //when(templateRepository.findByCredentialTypeAndContext("MockVerifiableCredential,VerifiableCredential", "https://vharsh.github.io/DID/mock-context.json,https://www.w3.org/2018/credentials/v1")).thenReturn(Optional.of(vc3));
        formatter.initialize();
//        engine = new VelocityEngine();
//        engine.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
//        engine.setProperty("classpath.resource.loader.class", ClasspathResourceLoader.class.getName());
//        engine.setProperty(RuntimeConstants.RUNTIME_LOG_LOGSYSTEM_CLASS, "org.apache.velocity.runtime.log.NullLogChute");
//        engine.setProperty(RuntimeConstants.INPUT_ENCODING, "UTF-8");
//        engine.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
//        engine.init();
    }

    private CredentialTemplate initTemplate(String template, String type, String context) {
        CredentialTemplate t = new CredentialTemplate();
        t.setTemplate(template);
        t.setCredentialType(type);
        t.setContext(context);
        return t;
    }

    @SneakyThrows
    @Test
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
        Map<String, Object> templateMap = Map.of("templateName", "MockVerifiableCredential,VerifiableCredential:https://example.org/Person.json,https://www.w3.org/ns/credentials/v2",
                "issuerURI", "https://example.com/fake-issuer");
        String actualJSON = formatter.format(ret, templateMap);
        String expectedJSON = """
                {"credentialSubject":{"face":"data:image\\/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAIAQMAAAD+wSzIAAAABlBMVEX\\/\\/\\/+\\/v7+jQ3Y5AAAADklEQVQI12P4AIX8EAgALgAD\\/aNpbtEAAAAASUVORK5CYII","gender":"female","province":"Fake Area","phone":"1234567890","postalCode":123,"fullName":"Amit Developer","addressLine1":["1","Fake building","Fake Area","Fake City","Near Fake Landmark"],"dateOfBirth":"01\\/01\\/2022","vcVer":"VC-V1","UIN":123456,"region":"FakeRegion","email":"amit@fakemail.com"},"validUntil":"02\\/02\\/2122","validFrom":"01\\/01\\/2022","type":["VerifiableCredential","MockVerifiableCredential"],"@context":["https:\\/\\/www.w3.org\\/ns\\/credentials\\/v2"],"issuer":"https:\\/\\/example.com\\/fake-issuer"}
                """;
        JsonAssertions.assertThatJson(actualJSON).isEqualTo(expectedJSON);
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
            JSONObject j = new JSONObject(actualJSON);
        } catch (JSONException e) {
            Assert.fail(e.getMessage());
        }
    }
}