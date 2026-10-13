package lk.gov.dmt.certify.plugin.model;

import java.util.Map;

public record VcData(Map<String, String> attributes) {
    public VcData {
        attributes = Map.copyOf(attributes);
        if (attributes.keySet().stream().anyMatch(key -> !key.matches("[a-z][a-zA-Z0-9]*"))) {
            throw new IllegalArgumentException("Invalid business attribute name");
        }
    }

    @Override
    public String toString() {
        return "VcData[attributes=<redacted>]";
    }
}
