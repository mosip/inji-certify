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
                () -> CredentialRequestValidator.isValid(cr));
    }

    @Test
    public void isValid_Ldp_VC() {
        CredentialRequest cr = new CredentialRequest();
        cr.setFormat(VCFormats.LDP_VC);
        cr.setCredential_definition(new CredentialDefinition());
        assertTrue(CredentialRequestValidator.isValid(cr));
    }

    @Test
    public void isValid_Sd_Jwt() {
        CredentialRequest cr = new CredentialRequest();
        cr.setFormat(VCFormats.VC_SD_JWT);
        cr.setVct("vct-fake");
        assertTrue(CredentialRequestValidator.isValid(cr));
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
        assertTrue(CredentialRequestValidator.isValid(cr));
    }
}