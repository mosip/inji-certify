package io.mosip.certify.core.validators;

import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.CredentialDefinition;
import io.mosip.certify.core.dto.CredentialRequest;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class CredentialRequestValidatorFactoryTest {

    CredentialRequestValidatorFactory factory;

    @Before
    public void setUp() {
        factory = new CredentialRequestValidatorFactory();
    }

    @Test
    public void isValid_invalidFormat() {
        CredentialRequest cr = new CredentialRequest();
        cr.setFormat("fake-format");
        assertFalse(factory.isValid(cr));
    }

    @Test
    public void isValid_LDP_true() {
        CredentialRequest cr = new CredentialRequest();
        cr.setFormat(VCFormats.LDP_VC);
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