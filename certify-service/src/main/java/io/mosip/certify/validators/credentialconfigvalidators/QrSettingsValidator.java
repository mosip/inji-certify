package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class QrSettingsValidator {

    private static final Pattern VELOCITY_VAR_PATTERN = Pattern.compile("\\$!?\\{?([a-zA-Z][a-zA-Z0-9_\\-#\\.]*)\\}?");

    /**
     * Validates qrSettings blocks for duplicate fields within a single block
     * and ensures referenced fields exist in the vcTemplate.
     *
     * @param qrSettings List of QR code configuration blocks
     * @param vcTemplate The VC Velocity template string
     */
    public static void validateQrSettings(List<Map<String, Object>> qrSettings, String vcTemplate) {
        if (qrSettings == null || qrSettings.isEmpty()) {
            return;
        }

        String decodedVcTemplate = decodeVcTemplate(vcTemplate);
        Set<String> templateVariables = extractTemplateVariables(decodedVcTemplate);

        for (Map<String, Object> blockMap : qrSettings) {
            if (blockMap == null || blockMap.isEmpty()) {
                continue;
            }

            Set<String> seenInBlock = new HashSet<>();
            extractAndValidateBlockVariables(blockMap, seenInBlock, templateVariables);
        }
    }

    /**
     * Decodes a Base64-encoded VC template string.
     * If the template is already raw JSON or invalid Base64, returns the raw input.
     *
     * @param vcTemplate The input VC template string (Base64 or raw JSON)
     * @return Decoded UTF-8 JSON string or raw input
     */
    private static String decodeVcTemplate(String vcTemplate) {
        if (vcTemplate == null || vcTemplate.isEmpty()) {
            return vcTemplate;
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(vcTemplate.trim());
            return new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ignored) {
            // If not base64 encoded or fails decoding, return raw vcTemplate
            return vcTemplate;
        }
    }

    /**
     * Extracts all Velocity variable names (e.g. ${fullName} -> "fullName")
     * from a decoded VC template.
     *
     * @param decodedVcTemplate The decoded JSON template string
     * @return Set of unique variable names found in the template
     */
    private static Set<String> extractTemplateVariables(String decodedVcTemplate) {
        Set<String> variables = new HashSet<>();
        if (decodedVcTemplate == null || decodedVcTemplate.isEmpty()) {
            return variables;
        }
        Matcher matcher = VELOCITY_VAR_PATTERN.matcher(decodedVcTemplate);
        while (matcher.find()) {
            variables.add(matcher.group(1));
        }
        return variables;
    }

    /**
     * Recursively traverses a QR settings block structure (maps, lists, strings),
     * checking for duplicate field references within the block and verifying
     * that referenced variables exist in the VC template.
     *
     * @param obj The element to traverse (Map, List, or String)
     * @param seenInBlock Set tracking variable names already encountered in the current block
     * @param templateVariables Set of valid variable names extracted from the VC template
     */
    private static void extractAndValidateBlockVariables(Object obj, Set<String> seenInBlock, Set<String> templateVariables) {
        if (obj == null) {
            return;
        }

        if (obj instanceof Map<?, ?> map) {
            for (Object value : map.values()) {
                extractAndValidateBlockVariables(value, seenInBlock, templateVariables);
            }
        } else if (obj instanceof List<?> list) {
            for (Object item : list) {
                extractAndValidateBlockVariables(item, seenInBlock, templateVariables);
            }
        } else if (obj instanceof String strVal) {
            Matcher matcher = VELOCITY_VAR_PATTERN.matcher(strVal);
            while (matcher.find()) {
                String varName = matcher.group(1);

                // 1. Check for duplicate field references within the single block
                if (!seenInBlock.add(varName)) {
                    throw new CertifyException(
                            ErrorConstants.DUPLICATE_FIELDS_IN_QR_SETTINGS,
                            "Duplicate field '" + varName + "' found in a single qrSettings block."
                    );
                }

                // 2. Check if field exists in templateVariables (if templateVariables is provided)
                if (templateVariables != null) {
                    if (!isFieldPresentInTemplate(varName, templateVariables)) {
                        throw new CertifyException(
                                ErrorConstants.QR_INVALID_FIELD_REFERENCE,
                                "Field '" + varName + "' referenced in qrSettings is not present in VC template."
                        );
                    }
                }
            }
        }
    }

    /**
     * Checks if a variable name or its base/terminal field in composite notation
     * exists within the set of valid template variables.
     *
     * @param varName The variable name referenced in QR settings
     * @param templateVariables Set of valid template variable names
     * @return true if the field or composite component exists in the template, false otherwise
     */
    private static boolean isFieldPresentInTemplate(String varName, Set<String> templateVariables) {
        if (templateVariables.contains(varName)) {
            return true;
        }
        // Handle composite key like address#en.country -> check base field 'address' or 'country'
        if (varName.contains("#") || varName.contains(".")) {
            String[] parts = varName.split("[#.]");
            String rootField = parts[0];
            String terminalField = parts[parts.length - 1];
            return templateVariables.contains(rootField) || templateVariables.contains(terminalField);
        }
        return false;
    }
}
