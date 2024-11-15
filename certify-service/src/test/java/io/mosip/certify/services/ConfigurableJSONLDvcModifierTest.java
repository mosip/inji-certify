package io.mosip.certify.services;

import lombok.SneakyThrows;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URISyntaxException;

import static org.junit.jupiter.api.Assertions.*;

class ConfigurableJSONLDvcModifierTest {
    ConfigurableJSONLDvcModifier modifier = new ConfigurableJSONLDvcModifier();
    @SneakyThrows
    @Test
    void perform() {
        JSONObject json = new JSONObject();
        json.put("item", "apple");
        JSONObject actual = modifier.perform(json.toString());
        assertDoesNotThrow(() -> URI.create(actual.get("id").toString()));
        assertTrue(actual.has("item"));
    }
}