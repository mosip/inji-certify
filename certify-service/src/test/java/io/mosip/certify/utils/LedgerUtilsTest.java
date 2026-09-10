/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.utils;

import io.mosip.certify.config.IndexedAttributesConfig;
import io.mosip.certify.core.dto.CredentialStatusDetail;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class LedgerUtilsTest {

    @Mock
    private IndexedAttributesConfig indexedAttributesConfig;

    @InjectMocks
    private LedgerUtils ledgerUtils;

    @Test
    public void extractCredentialType_arrayIsSortedAndJoined() {
        JSONObject json = new JSONObject().put("type", new JSONArray().put("VerifiableCredential").put("AbcCredential"));
        assertEquals("AbcCredential,VerifiableCredential", LedgerUtils.extractCredentialType(json));
    }

    @Test
    public void extractCredentialType_singleString() {
        JSONObject json = new JSONObject().put("type", "MyCredential");
        assertEquals("MyCredential", LedgerUtils.extractCredentialType(json));
    }

    @Test
    public void extractCredentialType_emptyArray_returnsDefault() {
        JSONObject json = new JSONObject().put("type", new JSONArray());
        assertEquals("VerifiableCredential", LedgerUtils.extractCredentialType(json));
    }

    @Test
    public void extractCredentialType_missingType_returnsDefault() {
        assertEquals("VerifiableCredential", LedgerUtils.extractCredentialType(new JSONObject()));
    }

    @Test
    public void extractCredentialType_blankString_returnsDefault() {
        JSONObject json = new JSONObject().put("type", "   ");
        assertEquals("VerifiableCredential", LedgerUtils.extractCredentialType(json));
    }

    @Test
    public void extractIndexedAttributes_nullJson_returnsEmpty() {
        assertTrue(ledgerUtils.extractIndexedAttributes(null).isEmpty());
    }

    @Test
    public void extractIndexedAttributes_noMappings_returnsEmpty() {
        when(indexedAttributesConfig.getIndexedMappings()).thenReturn(new LinkedHashMap<>());
        assertTrue(ledgerUtils.extractIndexedAttributes(new JSONObject().put("a", "b")).isEmpty());
    }

    @Test
    public void extractIndexedAttributes_extractsScalar() {
        Map<String, String> mappings = new LinkedHashMap<>();
        mappings.put("name", "$.credentialSubject.name");
        when(indexedAttributesConfig.getIndexedMappings()).thenReturn(mappings);

        JSONObject json = new JSONObject().put("credentialSubject", new JSONObject().put("name", "John"));
        Map<String, Object> result = ledgerUtils.extractIndexedAttributes(json);
        assertEquals("John", result.get("name"));
    }

    @Test
    public void extractIndexedAttributes_fallbackPathUsed() {
        Map<String, String> mappings = new LinkedHashMap<>();
        mappings.put("id", "$.missing.field|$.credentialSubject.id");
        when(indexedAttributesConfig.getIndexedMappings()).thenReturn(mappings);

        JSONObject json = new JSONObject().put("credentialSubject", new JSONObject().put("id", "abc-123"));
        Map<String, Object> result = ledgerUtils.extractIndexedAttributes(json);
        assertEquals("abc-123", result.get("id"));
    }

    @Test
    public void extractIndexedAttributes_missingValue_skipped() {
        Map<String, String> mappings = new LinkedHashMap<>();
        mappings.put("missing", "$.credentialSubject.absent");
        when(indexedAttributesConfig.getIndexedMappings()).thenReturn(mappings);

        JSONObject json = new JSONObject().put("credentialSubject", new JSONObject().put("name", "John"));
        assertTrue(ledgerUtils.extractIndexedAttributes(json).isEmpty());
    }

    @Test
    public void extractCredentialStatusDetails_present() {
        JSONObject status = new JSONObject()
                .put("statusPurpose", "revocation")
                .put("statusListIndex", "42")
                .put("statusListCredential", "https://issuer/status/list-99");
        JSONObject json = new JSONObject().put("credentialStatus", status);

        CredentialStatusDetail detail = ledgerUtils.extractCredentialStatusDetails(json);

        assertNotNull(detail);
        assertEquals("revocation", detail.getStatusPurpose());
        assertEquals(Long.valueOf(42), detail.getStatusListIndex());
        assertEquals("list-99", detail.getStatusListCredentialId());
        assertNotNull(detail.getCreatedTimes());
    }

    @Test
    public void extractCredentialStatusDetails_noSlashInUrl_usesFullUrl() {
        JSONObject status = new JSONObject()
                .put("statusPurpose", "revocation")
                .put("statusListIndex", "1")
                .put("statusListCredential", "list-only");
        JSONObject json = new JSONObject().put("credentialStatus", status);

        CredentialStatusDetail detail = ledgerUtils.extractCredentialStatusDetails(json);
        assertEquals("list-only", detail.getStatusListCredentialId());
    }

    @Test
    public void extractCredentialStatusDetails_absent_returnsNull() {
        assertNull(ledgerUtils.extractCredentialStatusDetails(new JSONObject()));
    }
}
