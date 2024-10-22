package io.mosip.certify.services;

import com.nimbusds.jose.JWSAlgorithm;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.SignatureAlg;
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

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

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
    }

    @Test
    public void testPerformSuccess_VC2() {
        // Mock Templated VC and Key Manager Input
        String VCs[] = new String[]{VC_1, VC_2};
        for (String templatedVC : VCs) {

            Map<String, String> keyMgrInput = new HashMap<>();
            keyMgrInput.put(KeyManagerConstants.PUBLIC_KEY_URL, "https://example.com/sample.pub.key.json/");
            keyMgrInput.put(KeyManagerConstants.KEY_APP_ID, KeyManagerConstants.CERTIFY_MOCK_RSA);
            keyMgrInput.put(KeyManagerConstants.KEY_REF_ID, KeyManagerConstants.EMPTY_REF_ID);
            keyMgrInput.put(KeyManagerConstants.VC_SIGN_ALGO, SignatureAlg.RSA_SIGNATURE_SUITE);
            keyMgrInput.put(KeyManagerConstants.KEYMGR_SIGN_ALGO, JWSAlgorithm.RS256.getName());

            // Mock Signature Service Response
            JWTSignatureResponseDto jwsSignedData = new JWTSignatureResponseDto();
            jwsSignedData.setJwtSignedData("mocked-jws");
            when(signatureService.jwsSign(any())).thenReturn(jwsSignedData);
            // Perform the test
            VCResult<JsonLDObject> vcResult = signer.perform(templatedVC, keyMgrInput);

            // Assertions
            Assert.assertNotNull(vcResult);
            JsonLDObject credential = vcResult.getCredential();
            Assert.assertNotNull(credential);
            Assert.assertNotNull(credential.getJsonObject().get(VCDMConstants.PROOF));
            Assert.assertNotNull(vcResult.getCredential().getJsonObject().containsKey("proof"));
            Map<String, Object> proof = (Map<String, Object>) credential.getJsonObject().get("proof");
            Assert.assertTrue(proof.containsKey("jws"));
            Assert.assertEquals("mocked-jws", proof.get("jws"));
        }
    }

}