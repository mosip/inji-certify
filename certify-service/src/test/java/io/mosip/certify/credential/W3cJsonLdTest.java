package io.mosip.certify.credential;

import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.credential.W3cJsonLd;
import io.mosip.certify.proofgenerators.ProofGenerator;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.service.SignatureService;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.LdProof;
import foundation.identity.jsonld.JsonLDObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class W3cJsonLdTest {

    @InjectMocks
    private W3cJsonLd w3cJsonLd;

    @Mock
    private VCFormatter vcFormatter;

    @Mock
    private SignatureService signatureService;

    @Mock
    private ProofGenerator proofGenerator;

    @Before
    public void setUp() {
//        vcFormatter = mock(VCFormatter.class);
//        signatureService = mock(SignatureService.class);
//        proofGenerator = mock(ProofGenerator.class);
//
//        w3cJsonLd = new W3cJsonLd(vcFormatter, signatureService);
//        w3cJsonLd.proofGenerator = proofGenerator;

        ReflectionTestUtils.setField(w3cJsonLd, "proofGenerator", proofGenerator);
    }

    @Test
    public void testCanHandleReturnsTrueForLdpVc() {
        assertTrue(w3cJsonLd.canHandle("ldp_vc"));
    }

    @Test
    public void testCanHandleReturnsFalseForOtherFormat() {
        assertFalse(w3cJsonLd.canHandle("jwt_vc"));
    }

    @Test
    public void testAddProofGeneratesCorrectVCResult() throws Exception {
        String vcJson = "{\"@context\":[],\"issuanceDate\":\"2023-01-01T00:00:00.000Z\"}";
        JsonLDObject jsonLDObject = JsonLDObject.fromJson(vcJson);

        Canonicalizer canonicalizer = mock(Canonicalizer.class);
        when(proofGenerator.getCanonicalizer()).thenReturn(canonicalizer);
        when(proofGenerator.getName()).thenReturn("RsaSignature2018");
        when(canonicalizer.canonicalize(any(LdProof.class), any(JsonLDObject.class)))
                .thenReturn("canonicalized".getBytes());

        LdProof ldProof = LdProof.builder()
                .type("RsaSignature2018")
                .created(new Date())
                .proofPurpose("assertionMethod")
                .verificationMethod(URI.create("https://example.com/key"))
                .build();

        when(proofGenerator.generateProof(any(LdProof.class), anyString(), anyMap())).thenReturn(ldProof);

        VCResult<?> result = w3cJsonLd.addProof(vcJson, null, "RS256", "appID", "refID", "https://example.com/key");

        assertEquals("ldp_vc", result.getFormat());
        assertNotNull(result.getCredential());
    }

    @Test
    public void testAddProofGeneratesCorrectVCResult_ValidFrom() throws Exception {
        String vcJson = "{\"@context\":[],\"validFrom\":\"2023-01-01T00:00:00.000Z\"}";
        JsonLDObject jsonLDObject = JsonLDObject.fromJson(vcJson);

        Canonicalizer canonicalizer = mock(Canonicalizer.class);
        when(proofGenerator.getCanonicalizer()).thenReturn(canonicalizer);
        when(proofGenerator.getName()).thenReturn("RsaSignature2018");
        when(canonicalizer.canonicalize(any(LdProof.class), any(JsonLDObject.class)))
                .thenReturn("canonicalized".getBytes());

        LdProof ldProof = LdProof.builder()
                .type("RsaSignature2018")
                .created(new Date())
                .proofPurpose("assertionMethod")
                .verificationMethod(URI.create("https://example.com/key"))
                .build();

        when(proofGenerator.generateProof(any(LdProof.class), anyString(), anyMap())).thenReturn(ldProof);

        VCResult<?> result = w3cJsonLd.addProof(vcJson, null, "RS256", "appID", "refID", "https://example.com/key");

        assertEquals("ldp_vc", result.getFormat());
        assertNotNull(result.getCredential());
    }

    @Test
    public void testAddProof_UsesCurrentTimeWhenNoDateProvided() throws Exception {
        String vcJson = "{\"@context\":[],\"id\":\"some-vc\"}"; // no issuanceDate or validFrom

        JsonLDObject jsonLDObject = JsonLDObject.fromJson(vcJson);

        Canonicalizer canonicalizer = mock(Canonicalizer.class);
        when(proofGenerator.getCanonicalizer()).thenReturn(canonicalizer);
        when(proofGenerator.getName()).thenReturn("TestProof");
        when(canonicalizer.canonicalize(any(LdProof.class), any(JsonLDObject.class)))
                .thenReturn("test".getBytes());

        LdProof ldProof = LdProof.builder()
                .type("TestProof")
                .created(new Date())
                .proofPurpose("assertionMethod")
                .verificationMethod(URI.create("https://example.com/key"))
                .build();

        when(proofGenerator.generateProof(any(), any(), anyMap())).thenReturn(ldProof);

        VCResult<?> result = w3cJsonLd.addProof(vcJson, null, "RS256", "appID", "refID", "https://example.com/key");

        assertNotNull(result);
        assertEquals("ldp_vc", result.getFormat());
        assertNotNull(result.getCredential());
    }

    @Test(expected = CertifyException.class)
    public void testAddProof_WhenCanonicalizerFails_ThrowsCertifyException() throws Exception {
        String vcJson = "{\"@context\":[],\"issuanceDate\":\"2023-01-01T00:00:00.000Z\"}";

        JsonLDObject jsonLDObject = JsonLDObject.fromJson(vcJson);

        Canonicalizer canonicalizer = mock(Canonicalizer.class);
        when(proofGenerator.getCanonicalizer()).thenReturn(canonicalizer);
        when(proofGenerator.getName()).thenReturn("TestProof");
        when(canonicalizer.canonicalize(any(LdProof.class), any(JsonLDObject.class)))
                .thenThrow(new IOException("Mocked IO failure"));

        // This will trigger the catch and rethrow CertifyException
        w3cJsonLd.addProof(vcJson, null, "RS256", "appID", "refID", "https://example.com/key");
    }


}
