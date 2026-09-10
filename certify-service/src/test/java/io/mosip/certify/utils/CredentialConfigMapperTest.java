/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.utils;

import io.mosip.certify.core.dto.ClaimsDTO;
import io.mosip.certify.core.dto.ClaimsDisplayFieldsConfigDTO;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.MetaDataDisplayDTO;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.attributes.Claims;
import io.mosip.certify.entity.attributes.MetaDataDisplay;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class CredentialConfigMapperTest {

    private CredentialConfigMapper mapper;

    @Before
    public void setup() {
        mapper = new CredentialConfigMapperImpl();
    }

    private MetaDataDisplayDTO buildMetaDataDisplayDTO() {
        MetaDataDisplayDTO.Logo logo = new MetaDataDisplayDTO.Logo();
        logo.setUri("https://logo.mosip.io");
        logo.setAltText("logo alt");
        MetaDataDisplayDTO.BackgroundImage bg = new MetaDataDisplayDTO.BackgroundImage();
        bg.setUri("https://bg.mosip.io");
        MetaDataDisplayDTO display = new MetaDataDisplayDTO();
        display.setLogo(logo);
        display.setBackgroundImage(bg);
        display.setName("Test Credential");
        display.setLocale("en");
        display.setTextColor("#000000");
        display.setBackgroundColor("#FFFFFF");
        return display;
    }

    private CredentialConfigurationDTO buildFullDto() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setVcTemplate("test_template");
        dto.setCredentialConfigKeyId("test-credential");
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1", "https://example.org/ctx"));
        dto.setCredentialTypes(List.of("VerifiableCredential", "TestVerifiableCredential"));
        dto.setCredentialFormat("ldp_vc");
        dto.setDidUrl("did:web:test.io");
        dto.setKeyManagerAppId("TEST2019");
        dto.setKeyManagerRefId("TEST2019-REF");
        dto.setSignatureAlgo("EdDSA");
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setSdClaim("name,email");
        dto.setMetaDataDisplay(List.of(buildMetaDataDisplayDTO()));
        dto.setDisplayOrder(List.of("name", "email"));
        dto.setScope("test_vc_ldp");
        dto.setDocType("org.iso.18013.5.1.mDL");
        dto.setSdJwtVct("TestVct");
        dto.setQrSignatureAlgo("RS256");

        dto.setClaims(Map.of("name",
                new ClaimsDTO(List.of(new ClaimsDTO.Display("Full Name", "en")))));
        dto.setMsoMdocClaims(Map.of("org.iso.18013.5.1",
                Map.of("given_name",
                        new ClaimsDisplayFieldsConfigDTO(List.of(
                                new ClaimsDisplayFieldsConfigDTO.Display("Given Name", "en"))))));
        dto.setSdJwtClaims(Map.of("email",
                new ClaimsDisplayFieldsConfigDTO(List.of(
                        new ClaimsDisplayFieldsConfigDTO.Display("Email", "en")))));
        dto.setPluginConfigurations(List.of(Map.of("key", "value")));
        dto.setCredentialStatusPurposes(List.of("revocation"));

        List<Map<String, Object>> qr = new ArrayList<>();
        qr.add(Map.of("size", 200));
        dto.setQrSettings(qr);
        return dto;
    }

    @Test
    public void toEntity_fullyPopulated_mapsAllFields() {
        CredentialConfigurationDTO dto = buildFullDto();

        CredentialConfig entity = mapper.toEntity(dto);

        assertNotNull(entity);
        assertEquals("test_template", entity.getVcTemplate());
        assertEquals("test-credential", entity.getCredentialConfigKeyId());
        // contextURLs are sorted and comma-joined
        assertEquals("https://example.org/ctx,https://www.w3.org/2018/credentials/v1", entity.getContext());
        assertEquals("TestVerifiableCredential,VerifiableCredential", entity.getCredentialType());
        assertEquals("ldp_vc", entity.getCredentialFormat());
        assertEquals("did:web:test.io", entity.getDidUrl());
        assertEquals("TEST2019", entity.getKeyManagerAppId());
        assertEquals("TEST2019-REF", entity.getKeyManagerRefId());
        assertEquals("EdDSA", entity.getSignatureAlgo());
        assertEquals("Ed25519Signature2020", entity.getSignatureCryptoSuite());
        assertEquals("name,email", entity.getSdClaim());
        assertEquals("test_vc_ldp", entity.getScope());
        assertEquals("org.iso.18013.5.1.mDL", entity.getDocType());
        assertEquals("TestVct", entity.getSdJwtVct());
        assertEquals("RS256", entity.getQrSignatureAlgo());
        assertEquals(List.of("name", "email"), entity.getOrder());
        assertNotNull(entity.getCreatedTimes());

        // Nested display
        assertEquals(1, entity.getDisplay().size());
        MetaDataDisplay md = entity.getDisplay().get(0);
        assertEquals("Test Credential", md.getName());
        assertEquals("en", md.getLocale());
        assertEquals("#000000", md.getTextColor());
        assertEquals("#FFFFFF", md.getBackgroundColor());
        assertEquals("https://logo.mosip.io", md.getLogo().getUri());
        assertEquals("logo alt", md.getLogo().getAltText());
        assertEquals("https://bg.mosip.io", md.getBackgroundImage().getUri());

        // Claims maps
        assertEquals("Full Name", entity.getClaims().get("name").getDisplay().get(0).getName());
        assertEquals("Given Name",
                entity.getMsoMdocClaims().get("org.iso.18013.5.1").get("given_name").getDisplay().get(0).getName());
        assertEquals("Email", entity.getSdJwtClaims().get("email").getDisplay().get(0).getName());
        assertEquals(List.of(Map.of("key", "value")), entity.getPluginConfigurations());
        assertEquals(List.of("revocation"), entity.getCredentialStatusPurposes());
        assertEquals(1, entity.getQrSettings().size());
    }

    @Test
    public void toDto_fullyPopulated_mapsAllFields() {
        CredentialConfig entity = mapper.toEntity(buildFullDto());

        CredentialConfigurationDTO dto = mapper.toDto(entity);

        assertNotNull(dto);
        assertEquals("test_template", dto.getVcTemplate());
        assertEquals("test-credential", dto.getCredentialConfigKeyId());
        // comma string split back to list
        assertEquals(List.of("https://example.org/ctx", "https://www.w3.org/2018/credentials/v1"), dto.getContextURLs());
        assertEquals(List.of("TestVerifiableCredential", "VerifiableCredential"), dto.getCredentialTypes());
        assertEquals("ldp_vc", dto.getCredentialFormat());
        assertEquals("test_vc_ldp", dto.getScope());
        assertEquals("org.iso.18013.5.1.mDL", dto.getDocType());
        assertEquals("TestVct", dto.getSdJwtVct());
        assertEquals(List.of("name", "email"), dto.getDisplayOrder());
        assertEquals(1, dto.getMetaDataDisplay().size());
        assertEquals("Test Credential", dto.getMetaDataDisplay().get(0).getName());
        assertEquals("https://logo.mosip.io", dto.getMetaDataDisplay().get(0).getLogo().getUri());
        assertEquals("https://bg.mosip.io", dto.getMetaDataDisplay().get(0).getBackgroundImage().getUri());
        assertEquals("Full Name", dto.getClaims().get("name").getDisplay().get(0).getName());
        assertEquals("Given Name",
                dto.getMsoMdocClaims().get("org.iso.18013.5.1").get("given_name").getDisplay().get(0).getName());
        assertEquals("Email", dto.getSdJwtClaims().get("email").getDisplay().get(0).getName());
    }

    @Test
    public void updateEntityFromDto_onEmptyEntity_populatesFields() {
        CredentialConfig entity = new CredentialConfig();
        CredentialConfigurationDTO dto = buildFullDto();

        mapper.updateEntityFromDto(dto, entity);

        assertEquals("test-credential", entity.getCredentialConfigKeyId());
        assertEquals("test_vc_ldp", entity.getScope());
        assertEquals(List.of("name", "email"), entity.getOrder());
        assertNotNull(entity.getUpdatedTimes());
        assertEquals("Full Name", entity.getClaims().get("name").getDisplay().get(0).getName());
        assertEquals("Email", entity.getSdJwtClaims().get("email").getDisplay().get(0).getName());
    }

    @Test
    public void updateEntityFromDto_onEntityWithExistingCollections_replacesThem() {
        // Pre-populate the entity so the "clear + putAll/addAll" branches are exercised
        CredentialConfig entity = mapper.toEntity(buildFullDto());
        assertNotNull(entity.getDisplay());
        assertNotNull(entity.getClaims());

        CredentialConfigurationDTO dto = buildFullDto();
        dto.setScope("updated_scope");
        dto.setDisplayOrder(List.of("email"));
        dto.setCredentialStatusPurposes(List.of("suspension"));
        dto.setPluginConfigurations(List.of(Map.of("k2", "v2")));
        List<Map<String, Object>> qr = new ArrayList<>();
        qr.add(Map.of("size", 100));
        dto.setQrSettings(qr);

        mapper.updateEntityFromDto(dto, entity);

        assertEquals("updated_scope", entity.getScope());
        assertEquals(List.of("email"), entity.getOrder());
        assertEquals(List.of("suspension"), entity.getCredentialStatusPurposes());
        assertEquals(List.of(Map.of("k2", "v2")), entity.getPluginConfigurations());
        assertEquals(1, entity.getQrSettings().size());
    }

    @Test
    public void updateEntityFromDto_withNullCollectionsOnPopulatedEntity_setsNull() {
        CredentialConfig entity = mapper.toEntity(buildFullDto());

        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setScope("only_scope");

        mapper.updateEntityFromDto(dto, entity);

        assertEquals("only_scope", entity.getScope());
        assertNull(entity.getDisplay());
        assertNull(entity.getOrder());
        assertNull(entity.getClaims());
        assertNull(entity.getMsoMdocClaims());
        assertNull(entity.getSdJwtClaims());
        assertNull(entity.getPluginConfigurations());
        assertNull(entity.getCredentialStatusPurposes());
        assertNull(entity.getQrSettings());
    }

    @Test
    public void nullInputs_returnNullOrNoop() {
        assertNull(mapper.toEntity((CredentialConfigurationDTO) null));
        assertNull(mapper.toDto((CredentialConfig) null));
        assertNull(mapper.toEntity((ClaimsDisplayFieldsConfigDTO) null));
        assertNull(mapper.toDto((Claims) null));

        CredentialConfig entity = new CredentialConfig();
        entity.setScope("unchanged");
        mapper.updateEntityFromDto(null, entity);
        assertEquals("unchanged", entity.getScope());
    }

    @Test
    public void claimsDisplayFieldsConfig_roundTrip() {
        ClaimsDisplayFieldsConfigDTO dto = new ClaimsDisplayFieldsConfigDTO(
                List.of(new ClaimsDisplayFieldsConfigDTO.Display("Name", "en")));

        Claims entity = mapper.toEntity(dto);
        assertEquals("Name", entity.getDisplay().get(0).getName());
        assertEquals("en", entity.getDisplay().get(0).getLocale());

        ClaimsDisplayFieldsConfigDTO back = mapper.toDto(entity);
        assertEquals("Name", back.getDisplay().get(0).getName());
        assertEquals("en", back.getDisplay().get(0).getLocale());
    }

    @Test
    public void listToCommaSeparatedString_variants() {
        assertNull(mapper.listToCommaSeparatedString(null));
        assertNull(mapper.listToCommaSeparatedString(List.of()));
        assertEquals("a,b,c", mapper.listToCommaSeparatedString(List.of("c", "a", "b")));
    }

    @Test
    public void commaSeparatedStringToList_variants() {
        assertTrue(mapper.commaSeparatedStringToList(null).isEmpty());
        assertTrue(mapper.commaSeparatedStringToList("").isEmpty());
        assertEquals(List.of("a", "b", "c"), mapper.commaSeparatedStringToList(" a , b ,c"));
    }

    @Test
    public void mapClaims_nullReturnsNull() {
        assertNull(mapper.mapClaims(null));
        assertNull(mapper.mapClaimsToDto(null));
    }

    @Test
    public void mapClaims_roundTrip() {
        Map<String, Map<String, ClaimsDisplayFieldsConfigDTO>> source = Map.of(
                "ns", Map.of("field", new ClaimsDisplayFieldsConfigDTO(
                        List.of(new ClaimsDisplayFieldsConfigDTO.Display("Field", "en")))));

        Map<String, Map<String, Claims>> entity = mapper.mapClaims(source);
        assertEquals("Field", entity.get("ns").get("field").getDisplay().get(0).getName());

        Map<String, Map<String, ClaimsDisplayFieldsConfigDTO>> back = mapper.mapClaimsToDto(entity);
        assertEquals("Field", back.get("ns").get("field").getDisplay().get(0).getName());
    }
}
