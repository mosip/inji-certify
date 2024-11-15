package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.services.ldsigner.ProofSignatureStrategy;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import org.json.JSONException;
import org.json.JSONObject;
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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import java.util.Map;

@RunWith(MockitoJUnitRunner.class)
public class KeymanagerLibSignerTest {
    @Mock
    SignatureService signatureService;
    @Mock
    ProofSignatureStrategy signProps;
    @InjectMocks
    private KeymanagerLibSigner signer;
    private static final String VC_1 = """
            {
                            "@context": [
                                "https://www.w3.org/ns/credentials/v2"
                            ],
                            "validFrom": "2024-09-22T23:06:22.123Z",
                            "validUntil": "2034-09-22T23:06:22.123Z",
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
                            "validUntil": "2034-09-22T23:06:22.123Z",
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
    }

    @Test
    public void testPerformSuccess_VC2() throws JSONException {
        // Mock Templated VC and Key Manager Input
        String[] VCs = new String[]{VC_1, VC_2};
        for (String templatedVC : VCs) {
            // Prepare a FakeSignature2018 implementation
            JWTSignatureResponseDto jwsSignedData = new JWTSignatureResponseDto();
            jwsSignedData.setJwtSignedData("mocked-jws");
            when(signatureService.jwsSign(any())).thenReturn(jwsSignedData);
            when(signProps.getName()).thenReturn("FakeSignature2018");
            when(signProps.getCanonicalizer()).thenReturn(new URDNA2015Canonicalizer());
            when(signProps.getProof(anyString())).thenReturn("fake-jws-proof");
            LdProof l = LdProof.builder().jws("fake-jws-proof").type("FakeSignature2018").proofPurpose("assertionMethod").build();
            when(signProps.buildProof(any(), any())).thenReturn(l);
            JSONObject json = new JSONObject(templatedVC);
            // invoke
            VCResult<JsonLDObject> vcResult = signer.perform(json);

            // test
            assert vcResult != null;
            JsonLDObject credential = vcResult.getCredential();
            Map<String, Object> proof = (Map<String, Object>) credential.getJsonObject().get("proof");
            Assert.assertEquals("fake-jws-proof", proof.get("jws"));
        }
    }

}