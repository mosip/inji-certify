package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class QrSettingsValidatorTest {

    private final String sampleVcTemplate = """
            {
              "credentialSubject": {
                "fullName": "${fullName}",
                "mobileNumber": "${mobileNumber}",
                "dateOfBirth": "${dateOfBirth}",
                "face": "${face}"
              }
            }
            """;

    @Test
    public void should_doNothing_when_qrSettingsNullOrEmpty() {
        assertDoesNotThrow(() -> QrSettingsValidator.validateQrSettings(null, sampleVcTemplate));
        assertDoesNotThrow(() -> QrSettingsValidator.validateQrSettings(Collections.emptyList(), sampleVcTemplate));
    }

    @Test
    public void should_validateSuccessfully_when_qrSettingsValidAndFieldsExistInVcTemplate() {
        List<Map<String, Object>> qrSettings = List.of(
                Map.of("Full Name", "${fullName}", "Phone", "${mobileNumber}"),
                Map.of("DOB", "${dateOfBirth}", "Photo", "${face}")
        );

        assertDoesNotThrow(() -> QrSettingsValidator.validateQrSettings(qrSettings, sampleVcTemplate));
    }

    @Test
    public void should_throwException_when_duplicateFieldsInSingleQrBlock() {
        List<Map<String, Object>> qrSettings = List.of(
                Map.of("Full Name", "${fullName}", "Name Duplicate", "${fullName}")
        );

        CertifyException ex = assertThrows(CertifyException.class,
                () -> QrSettingsValidator.validateQrSettings(qrSettings, sampleVcTemplate));

        assertEquals(ErrorConstants.DUPLICATE_FIELDS_IN_QR_SETTINGS, ex.getErrorCode());
        assertTrue(ex.getMessage().contains("Duplicate field 'fullName'"));
    }

    @Test
    public void should_throwException_when_fieldReferencedInQrSettingsMissingFromVcTemplate() {
        List<Map<String, Object>> qrSettings = List.of(
                Map.of("Full Name", "${fullName}", "Invalid Field", "${unsupportedField}")
        );

        CertifyException ex = assertThrows(CertifyException.class,
                () -> QrSettingsValidator.validateQrSettings(qrSettings, sampleVcTemplate));

        assertEquals(ErrorConstants.QR_INVALID_FIELD_REFERENCE, ex.getErrorCode());
        assertTrue(ex.getMessage().contains("Field 'unsupportedField'"));
    }

    @Test
    public void should_allowSameFieldInDifferentBlocks_when_fieldsInSeparateBlocks() {
        List<Map<String, Object>> qrSettings = List.of(
                Map.of("Full Name Block 1", "${fullName}"),
                Map.of("Full Name Block 2", "${fullName}")
        );

        assertDoesNotThrow(() -> QrSettingsValidator.validateQrSettings(qrSettings, sampleVcTemplate));
    }

    @Test
    public void should_validateSuccessfully_when_vcTemplateIsBase64Encoded() {
        String base64Template = java.util.Base64.getEncoder().encodeToString(sampleVcTemplate.getBytes());
        List<Map<String, Object>> qrSettings = List.of(
                Map.of("Full Name", "${fullName}", "Phone", "${mobileNumber}")
        );

        assertDoesNotThrow(() -> QrSettingsValidator.validateQrSettings(qrSettings, base64Template));
    }

    @Test
    public void should_throwException_when_fieldIsSubstringOfTemplateVariable() {
        List<Map<String, Object>> qrSettings = List.of(
                Map.of("Short Name", "${name}")
        );

        CertifyException ex = assertThrows(CertifyException.class,
                () -> QrSettingsValidator.validateQrSettings(qrSettings, sampleVcTemplate));

        assertEquals(ErrorConstants.QR_INVALID_FIELD_REFERENCE, ex.getErrorCode());
        assertTrue(ex.getMessage().contains("Field 'name'"));
    }

    @Test
    public void should_throwException_when_vcTemplateHasNoVariablesButQrSettingsHasField() {
        String emptyVcTemplate = "{\"credentialSubject\": {}}";
        List<Map<String, Object>> qrSettings = List.of(
                Map.of("Field", "${unknownField}")
        );

        CertifyException ex = assertThrows(CertifyException.class,
                () -> QrSettingsValidator.validateQrSettings(qrSettings, emptyVcTemplate));

        assertEquals(ErrorConstants.QR_INVALID_FIELD_REFERENCE, ex.getErrorCode());
    }

    @Test
    public void should_validateSuccessfully_when_compositeFieldMatchesTerminalFieldInTemplate() {
        String templateWithTerminal = "{\"credentialSubject\": {\"country\": \"${country}\"}}";
        List<Map<String, Object>> qrSettings = List.of(
                Map.of("Country", "${address#en.country}")
        );

        assertDoesNotThrow(() -> QrSettingsValidator.validateQrSettings(qrSettings, templateWithTerminal));
    }

    @Test
    public void should_ignoreCurrencyLiterals_when_qrSettingsContainsDollarAmount() {
        List<Map<String, Object>> qrSettings = List.of(
                Map.of("Full Name", "${fullName}", "Price", "Amount: $2.50")
        );

        assertDoesNotThrow(() -> QrSettingsValidator.validateQrSettings(qrSettings, sampleVcTemplate));
    }
}
