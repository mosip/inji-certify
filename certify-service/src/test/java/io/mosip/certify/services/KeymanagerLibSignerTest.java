package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.services.proofgenerators.ProofGenerator;
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
    SignatureService signatureService;
    @Mock
    ProofGenerator signProps;
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
        ReflectionTestUtils.setField(signer, "issuerPublicKeyURI", "https://example.com/sample.pub.key.json/");
    }

    @Test
    public void testAttachSignatureSuccess_VC2() {
        // Mock Templated VC and Key Manager Input
        String VCs[] = new String[]{VC_1, VC_2};
        for (String templatedVC : VCs) {
            // Prepare a FakeSignature2018 implementation
            JWTSignatureResponseDto jwsSignedData = new JWTSignatureResponseDto();
            jwsSignedData.setJwtSignedData("mocked-jws");
            when(signatureService.jwsSign(any())).thenReturn(jwsSignedData);
            when(signProps.getName()).thenReturn("FakeSignature2018");
            when(signProps.getCanonicalizer()).thenReturn(new URDNA2015Canonicalizer());
            LdProof l = LdProof.builder().jws("fake-jws-proof").type("FakeSignature2018").proofPurpose("assertionMethod").build();
            when(signProps.generateProof(any(), any())).thenReturn(l);

            // invoke
            VCResult<JsonLDObject> vcResult = signer.attachSignature(templatedVC);

            // test
            assert vcResult != null;
            JsonLDObject credential = vcResult.getCredential();
            Assert.assertNotNull(credential.getJsonObject().containsKey("proof"));
            Map<String, Object> proof = (Map<String, Object>) credential.getJsonObject().get("proof");
            Assert.assertEquals("fake-jws-proof", proof.get("jws"));
        }
    }

}