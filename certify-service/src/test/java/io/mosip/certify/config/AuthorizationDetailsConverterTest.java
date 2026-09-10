package io.mosip.certify.config;

import io.mosip.certify.core.dto.AuthorizationDetail;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class AuthorizationDetailsConverterTest {

    private final AuthorizationDetailsConverter converter = new AuthorizationDetailsConverter();

    @Test
    public void convert_null_returnsNull() {
        assertNull(converter.convert(null));
    }

    @Test
    public void convert_empty_returnsNull() {
        assertNull(converter.convert("   "));
    }

    @Test
    public void convert_validJson_returnsList() {
        String json = "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"MockVC\"}]";
        List<AuthorizationDetail> result = converter.convert(json);
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("openid_credential", result.get(0).getType());
    }

    @Test
    public void convert_emptyArray_returnsEmptyList() {
        List<AuthorizationDetail> result = converter.convert("[]");
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    public void convert_invalidJson_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class, () -> converter.convert("not-json"));
    }
}
