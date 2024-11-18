package io.mosip.certify.services;

import lombok.SneakyThrows;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

class ConfigurableJSONLDvcModifierTest {
    ConfigurableJSONLDvcModifier modifier = new ConfigurableJSONLDvcModifier();
    @SneakyThrows
    @Test
    void perform() {
        JSONObject json = new JSONObject();
        json.put("item", "apple");
        JSONObject actual = modifier.perform(json.toString());
        // assert that the id field is a valid URI :: as per the spec
        assertDoesNotThrow(() -> URI.create(actual.get("id").toString()));
        assertTrue(actual.has("item"));
    }
}