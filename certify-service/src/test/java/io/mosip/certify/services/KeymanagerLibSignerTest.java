package io.mosip.certify.services;

import com.nimbusds.jose.JWSAlgorithm;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import io.mosip.kernel.signature.service.SignatureService;
import com.fasterxml.jackson.databind.JsonNode; // Assuming JsonLDObject extends JsonNode

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class KeymanagerLibSignerTest {

    @Mock
    private SignatureService signatureService;
    private KeymanagerLibSigner signer;

    @Before
    public void setup() {

    }

    @Test
    public void testPerformSuccess() throws Exception {
        // Mock Templated VC and Key Manager Input
        String templatedVC = """
                {"@context":["https://www.w3.org/ns/credentials/v2","https://www.w3.org/ns/credentials/examples/v2"],"type":["VerifiableCredential","MyPrototypeCredential"],"credentialSubject":{"mySubjectProperty":"mySubjectValue"}}
                """;
        Map<String, String> keyMgrInput = new HashMap<>();
        keyMgrInput.put("pubKey", "https://example.com/pub-key.json");
        keyMgrInput.put("vcSigner", SignatureAlg.RSA_SIGNATURE_SUITE);
        keyMgrInput.put("keyType", JWSAlgorithm.RS256.getName());
        keyMgrInput.put("keyManagerAppId", Constants.CERTIFY_MOCK_RSA);
        keyMgrInput.put("keyManagerRefID", "");

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
        Assert.assertTrue(credential.getJsonObject.("proof"));
        JsonNode proof = credential.get("proof");
        Assert.assertTrue(proof.has("jws"));
        Assert.assertEquals("mocked-jws", proof.get("jws").asText());
    }
}