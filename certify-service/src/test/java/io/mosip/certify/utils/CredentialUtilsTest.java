package io.mosip.certify.utils;

import io.mosip.certify.api.dto.VCRequestDto;
import junit.framework.TestCase;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.util.List;

public class CredentialUtilsTest extends TestCase {

    public void testGetTemplateName() {
        VCRequestDto request = new VCRequestDto();
        request.setContext(List.of("https://www.w3.org/ns/credentials/v2", "https://example.org/Person.json"));
        request.setType(List.of("VerifiableCredential", "UniversityCredential"));
        String expected = "UniversityCredential,VerifiableCredential:https://example.org/Person.json,https://www.w3.org/ns/credentials/v2";
        assertEquals(expected, CredentialUtils.getTemplateName(request));
    }
}