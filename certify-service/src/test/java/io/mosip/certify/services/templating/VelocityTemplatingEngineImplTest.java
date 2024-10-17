package io.mosip.certify.services.templating;

import io.mosip.certify.core.entity.TemplateData;
import io.mosip.certify.core.repository.TemplateRepository;
import junit.framework.TestCase;
import lombok.SneakyThrows;
import net.javacrumbs.jsonunit.assertj.JsonAssertions;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.when;

@Service
@RunWith(MockitoJUnitRunner.class)
public class VelocityTemplatingEngineImplTest extends TestCase {
    @InjectMocks
    private VelocityTemplatingEngineImpl formatter;
    @Mock
    TemplateRepository templateRepository;

    @Before
    public void setUp() {
        List<TemplateData> templates = new ArrayList<>();
        TemplateData vc1 = initTemplate("""
                
                {
                    "@context": [
                    "https://www.w3.org/2018/credentials/v1"]
                    "issuer": "${issuer}",
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
        TemplateData vc2 = initTemplate("""
                        {
                            "@context": [
                                    "https://www.w3.org/ns/credentials/v2"],
                            "issuer": "${issuer}",
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
        when(templateRepository.findAll()).thenReturn(List.of(vc1, vc2));
        formatter.initialize();
//        engine = new VelocityEngine();
//        engine.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
//        engine.setProperty("classpath.resource.loader.class", ClasspathResourceLoader.class.getName());
//        engine.setProperty(RuntimeConstants.RUNTIME_LOG_LOGSYSTEM_CLASS, "org.apache.velocity.runtime.log.NullLogChute");
//        engine.setProperty(RuntimeConstants.INPUT_ENCODING, "UTF-8");
//        engine.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
//        engine.init();
    }

    private TemplateData initTemplate(String template, String type, String context) {
        TemplateData t = new TemplateData();
        t.setTemplate(template);
        t.setCredentialType(type);
        t.setContext(context);
        return t;
    }

    @SneakyThrows
    @Test
    public void testTemplating() {
        // 1. setup template
        Resource cr = new ClassPathResource("MockCredential1.vm");
        assert cr.isFile();
        String t = Files.readString(cr.getFile().toPath(), StandardCharsets.UTF_8);
        assert t != null;
        Map<String, Object> ret = new HashMap<>();
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
}