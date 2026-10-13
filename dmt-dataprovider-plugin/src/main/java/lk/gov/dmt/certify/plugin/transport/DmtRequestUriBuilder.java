package lk.gov.dmt.certify.plugin.transport;

import lk.gov.dmt.certify.plugin.validation.EndpointTemplates;
import lk.gov.dmt.certify.plugin.validation.TextValidation;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static lk.gov.dmt.certify.plugin.error.DmtExchangeErrors.*;

/** Expands named variables as single path segments on the configured origin. */
final class DmtRequestUriBuilder {
    private DmtRequestUriBuilder() {}

    static URI requestUri(URI base, String endpoint, Map<String, String> pathVariables) throws ExchangeFailure {
        var requiredVariables = EndpointTemplates.variables(endpoint);
        if (pathVariables == null || !pathVariables.keySet().equals(requiredVariables)) {
            throw error(Failure.INVALID_LOOKUP);
        }
        String expanded = endpoint;
        for (String variable : requiredVariables) {
            String value = pathVariables.get(variable);
            if (value == null || value.isBlank() || value.length() > 512 || value.equals(".") || value.equals("..")
                    || TextValidation.controls(value)
                    || value.chars().anyMatch(c -> c == '%' || c == '/' || c == 92 || c == '?' || c == '#')) {
                throw error(Failure.INVALID_LOOKUP);
            }
            expanded = expanded.replace("{" + variable + "}", encodeSegment(value));
        }
        String prefix = base.toASCIIString().replaceAll("/+$", "");
        URI uri = URI.create(prefix + expanded);
        if (!uri.getScheme().equalsIgnoreCase(base.getScheme()) || !uri.getRawAuthority().equals(base.getRawAuthority())
                || !uri.normalize().equals(uri) || !uri.getRawPath().startsWith(base.getRawPath().replaceAll("/+$", "") + "/")) {
            throw error(Failure.INVALID_LOOKUP);
        }
        return uri;
    }

    private static String encodeSegment(String value) {
        StringBuilder encoded = new StringBuilder();
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xff;
            if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
                    || c == '-' || c == '_' || c == '.' || c == '~') {
                encoded.append((char) c);
            } else {
                encoded.append('%').append(Character.toUpperCase(Character.forDigit(c >>> 4, 16)))
                        .append(Character.toUpperCase(Character.forDigit(c & 15, 16)));
            }
        }
        return encoded.toString();
    }
}
