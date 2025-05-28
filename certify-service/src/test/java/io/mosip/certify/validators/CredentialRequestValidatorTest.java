package io.mosip.certify.validators;

import java.util.List;
import java.util.Map;

import io.mosip.certify.core.exception.InvalidRequestException;
import org.junit.Test;

import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.CredentialDefinition;
import io.mosip.certify.core.dto.CredentialRequest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.Assert.*;

public class CredentialRequestValidatorTest {

    CredentialRequestValidator factory;

    @Test
    public void isValid_invalidFormat() {
        CredentialRequest cr = new CredentialRequest();
        cr.setFormat("fake-format");
        assertThrows(InvalidRequestException.class,
                () -> factory.isValid(cr));
    }

    @ParameterizedTest
    @ValueSource(strings = {VCFormats.LDP_VC, VCFormats.SD_JWT})
    public void isValid(String format) {
        CredentialRequest cr = new CredentialRequest();
        cr.setFormat(format);
        cr.setCredential_definition(new CredentialDefinition());
        assertTrue(factory.isValid(cr));
    }

    @Test
    public void isValid_mDoc_true() {
        CredentialRequest cr = new CredentialRequest();
        cr.setFormat(VCFormats.MSO_MDOC);
        cr.setDoctype("mDoc-doctype-fake");
        cr.setClaims(Map.of("isAge", "21"));
        CredentialDefinition cd = new CredentialDefinition();
        cd.setType(List.of("VerifiableCredential", "MockDrivingLicense"));
        cd.setContext(List.of("https://example.context.page.sh"));
        cr.setCredential_definition(new CredentialDefinition());
        assertTrue(factory.isValid(cr));
    }
}