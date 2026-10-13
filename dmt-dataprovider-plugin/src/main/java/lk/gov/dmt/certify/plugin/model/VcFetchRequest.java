package lk.gov.dmt.certify.plugin.model;

import java.util.Map;

public record VcFetchRequest(String vcType, String selectedScope, String subject,
                             String issuer, String correlationId, Map<String, String> lookupAttributes) {
    public VcFetchRequest {
        if (vcType == null || selectedScope == null || subject == null || issuer == null
                || correlationId == null || subject.isBlank() || issuer.isBlank()) {
            throw new IllegalArgumentException("Incomplete provider request");
        }
        lookupAttributes = lookupAttributes == null ? Map.of() : Map.copyOf(lookupAttributes);
    }

    @Override
    public String toString() {
        return "VcFetchRequest[vcType=" + vcType + ", identity=<redacted>, lookup=<redacted>]";
    }
}
