package lk.gov.dmt.certify.plugin.application;

import io.mosip.certify.api.spi.DataProviderPlugin;
import lk.gov.dmt.certify.plugin.model.VcFetchRequest;
import lk.gov.dmt.certify.plugin.validation.TextValidation;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static lk.gov.dmt.certify.plugin.error.DmtExchangeErrors.*;

/** Converts authenticated claims into a bounded, immutable provider request. */
public final class ProviderRequestFactory {
    public String selectedScope(Map<String, Object> claims) throws ExchangeFailure {
        String selectedScope = requiredClaim(claims, DataProviderPlugin.SELECTED_SCOPE);
        String scopes = requiredClaim(claims, "scope");
        if (Arrays.stream(scopes.split(" ")).noneMatch(selectedScope::equals)) {
            throw error(Failure.INVALID_IDENTITY);
        }
        return selectedScope;
    }

    public VcFetchRequest create(String vcType, String selectedScope, Map<String, Object> claims,
                                 String correlationId) throws ExchangeFailure {
        return new VcFetchRequest(vcType, selectedScope, requiredClaim(claims, "sub"),
                requiredClaim(claims, "iss"), correlationId, lookupAttributes(claims));
    }

    private static String requiredClaim(Map<String, Object> claims, String key) throws ExchangeFailure {
        Object value = claims == null ? null : claims.get(key);
        if (!(value instanceof String text) || text.isBlank() || text.length() > 8192
                || TextValidation.controls(text)) throw error(Failure.INVALID_IDENTITY);
        return text;
    }

    /** The lookup claim must originate from the authenticated, issuer-validated token. */
    private static Map<String, String> lookupAttributes(Map<String, Object> claims) throws ExchangeFailure {
        Object value = claims.get("credential_lookup");
        if (value == null && !claims.containsKey("credential_lookup")) return Map.of();
        if (!(value instanceof Map<?, ?> attributes) || attributes.size() > 16) {
            throw error(Failure.INVALID_LOOKUP);
        }
        Map<String, String> result = new HashMap<>();
        for (var entry : attributes.entrySet()) {
            if (!(entry.getKey() instanceof String key) || !key.matches("[a-z][a-zA-Z0-9]{0,63}")
                    || !(entry.getValue() instanceof String text) || text.isBlank() || text.length() > 512
                    || TextValidation.controls(text)) {
                throw error(Failure.INVALID_LOOKUP);
            }
            result.put(key, text);
        }
        return Map.copyOf(result);
    }
}
