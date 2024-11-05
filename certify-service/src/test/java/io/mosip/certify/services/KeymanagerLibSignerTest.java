package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.VCDMConstants;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import io.mosip.kernel.signature.service.SignatureService;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.util.Map;

@RunWith(MockitoJUnitRunner.class)
public class KeymanagerLibSignerTest {

    @Mock
    private SignatureService signatureService;
    @InjectMocks
    private KeymanagerLibSigner signer;
    private static final String VC_1 = """
            {
                            "@context": [
                                "https://www.w3.org/ns/credentials/v2"
                            ],
                            "validFrom": "2024-09-22T23:06:22.123Z",
                            "type": [
                                "VerifiableCredential",
                                "MyPrototypeCredential"
                            ],
                            "credentialSubject": {
                                "mySubjectProperty": "mySubjectValue"
                            }
                        }
            """;
    private static final String VC_2 = """
            {
                            "@context": [
                                "https://www.w3.org/ns/credentials/v2"
                            ],
                            "validFrom": "2024-09-22T23:06:22.123Z",
                            "type": [
                                "VerifiableCredential",
                                "MyPrototypeCredential"
                            ],
                            "credentialSubject": {
                                "mySubjectProperty": "mySubjectValue"
                            }
            }""";

    @Before
    public void setup() {
        ReflectionTestUtils.setField(signer, "hostedKey", "https://example.com/sample.pub.key.json/");
        ReflectionTestUtils.setField(signer, "signProps", new RsaSignature2018());
    }

    @Test
    public void testPerformSuccess_VC2() {
        // Mock Templated VC and Key Manager Input
        String VCs[] = new String[]{VC_1, VC_2};
        for (String templatedVC : VCs) {
            // Mock Signature Service Response
            JWTSignatureResponseDto jwsSignedData = new JWTSignatureResponseDto();
            jwsSignedData.setJwtSignedData("mocked-jws");
            when(signatureService.jwsSign(any())).thenReturn(jwsSignedData);
            // Perform the test
            VCResult<JsonLDObject> vcResult = signer.perform(templatedVC);

            // Assertions
            assert vcResult != null;
            JsonLDObject credential = vcResult.getCredential();
            Assert.assertNotNull(credential.getJsonObject().get(VCDMConstants.PROOF));
            Assert.assertNotNull(vcResult.getCredential().getJsonObject().containsKey("proof"));
            Map<String, Object> proof = (Map<String, Object>) credential.getJsonObject().get("proof");
            Assert.assertTrue(proof.containsKey("jws"));
            Assert.assertEquals("mocked-jws", proof.get("jws"));
        }
    }

}