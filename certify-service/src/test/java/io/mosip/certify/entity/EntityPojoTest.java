package io.mosip.certify.entity;

import io.mosip.certify.core.dto.CredentialStatusDetail;
import io.mosip.certify.entity.attributes.Claims;
import io.mosip.certify.entity.attributes.CredentialSubjectParameters;
import io.mosip.certify.entity.attributes.MetaDataDisplay;
import org.junit.Test;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Exercises the JPA entities and attribute POJOs: constructors, accessors,
 * equals/hashCode/toString and the protected lifecycle callbacks.
 */
public class EntityPojoTest {

    @Test
    public void credentialStatusTransaction_gettersSettersAndLifecycle() {
        CredentialStatusTransaction tx = new CredentialStatusTransaction();
        tx.setTransactionLogId(1L);
        tx.setCredentialId("cred-1");
        tx.setStatusPurpose("revocation");
        tx.setStatusValue(Boolean.TRUE);
        tx.setStatusListCredentialId("slc-1");
        tx.setStatusListIndex(5L);
        tx.setProcessedTime(LocalDateTime.now());

        assertEquals(Long.valueOf(1L), tx.getTransactionLogId());
        assertEquals("cred-1", tx.getCredentialId());
        assertEquals("revocation", tx.getStatusPurpose());
        assertTrue(tx.getStatusValue());
        assertEquals("slc-1", tx.getStatusListCredentialId());
        assertEquals(Long.valueOf(5L), tx.getStatusListIndex());

        tx.onCreate();
        assertNotNull(tx.getCreatedDtimes());
        assertFalse(tx.getIsProcessed());

        tx.setIsProcessed(null);
        tx.onCreate();
        assertFalse(tx.getIsProcessed());

        CredentialStatusTransaction all = new CredentialStatusTransaction(
                2L, "c", "p", Boolean.FALSE, "s", 9L,
                LocalDateTime.now(), LocalDateTime.now(), Boolean.TRUE);
        assertEquals("c", all.getCredentialId());
        assertNotNull(all.toString());
        assertNotEquals(tx, all);
        assertNotEquals(tx.hashCode(), all.hashCode());
    }

    @Test
    public void ledger_gettersSettersAndLifecycle() {
        Ledger ledger = new Ledger();
        ledger.setId(1L);
        ledger.setCredentialId("cred");
        ledger.setIssuerId("issuer");
        ledger.setCredentialType("MockType");
        ledger.setIssuanceDate(LocalDateTime.now());
        ledger.setExpirationDate(LocalDateTime.now().plusDays(1));
        ledger.setIndexedAttributes(Map.of("k", "v"));
        ledger.setCredentialStatusDetails(List.of(new CredentialStatusDetail()));

        assertEquals("cred", ledger.getCredentialId());
        assertEquals("issuer", ledger.getIssuerId());
        assertEquals("MockType", ledger.getCredentialType());
        assertEquals(1, ledger.getIndexedAttributes().size());

        ledger.onCreate();
        assertNotNull(ledger.getCreatedDtimes());
        assertEquals(1, ledger.getCredentialStatusDetails().size());

        Ledger empty = new Ledger();
        empty.onCreate();
        assertNotNull(empty.getCredentialStatusDetails());
        assertTrue(empty.getCredentialStatusDetails().isEmpty());
        assertNotNull(empty.toString());
    }

    @Test
    public void statusListCredential_gettersSettersAndEnum() {
        StatusListCredential slc = new StatusListCredential();
        slc.setId("id-1");
        slc.setVcDocument("{}");
        slc.setCredentialType("BitstringStatusListCredential");
        slc.setStatusPurpose("revocation");
        slc.setCapacityInKB(64L);
        slc.setCredentialStatus(StatusListCredential.CredentialStatus.AVAILABLE);
        slc.setCreatedDtimes(LocalDateTime.now());
        slc.setUpdatedDtimes(LocalDateTime.now());

        assertEquals("id-1", slc.getId());
        assertEquals(StatusListCredential.CredentialStatus.AVAILABLE, slc.getCredentialStatus());
        assertEquals(StatusListCredential.CredentialStatus.FULL,
                StatusListCredential.CredentialStatus.valueOf("FULL"));
        assertEquals(2, StatusListCredential.CredentialStatus.values().length);
        assertNotNull(slc.toString());

        StatusListCredential same = new StatusListCredential();
        same.setId("id-1");
        same.setVcDocument("{}");
        same.setCredentialType("BitstringStatusListCredential");
        same.setStatusPurpose("revocation");
        same.setCapacityInKB(64L);
        same.setCredentialStatus(StatusListCredential.CredentialStatus.AVAILABLE);
        same.setCreatedDtimes(slc.getCreatedDtimes());
        same.setUpdatedDtimes(slc.getUpdatedDtimes());
        assertEquals(slc, same);
        assertEquals(slc.hashCode(), same.hashCode());
    }

    @Test
    public void statusListAvailableIndices_gettersSettersAndLifecycle() {
        StatusListAvailableIndices idx = new StatusListAvailableIndices();
        idx.setId(3L);
        idx.setStatusListCredentialId("slc");
        idx.setListIndex(10L);
        idx.setIsAssigned(Boolean.TRUE);
        idx.setStatusListCredential(new StatusListCredential());

        assertEquals(Long.valueOf(10L), idx.getListIndex());
        assertTrue(idx.getIsAssigned());
        assertNotNull(idx.getStatusListCredential());

        idx.onCreate();
        assertNotNull(idx.getCreatedDtimes());

        StatusListAvailableIndices nullAssigned = new StatusListAvailableIndices();
        nullAssigned.setIsAssigned(null);
        nullAssigned.onCreate();
        assertFalse(nullAssigned.getIsAssigned());

        idx.onUpdate();
        assertNotNull(idx.getUpdatedDtimes());
        assertNotNull(idx.toString());
    }

    @Test
    public void iarSession_gettersSettersAndLifecycle() {
        IarSession s = new IarSession();
        s.setId(1L);
        s.setAuthSession("auth");
        s.setTransactionId("txn");
        s.setRequestId("req");
        s.setVerifyNonce("nonce");
        s.setExpiresAt(LocalDateTime.now().plusMinutes(5));
        s.setClientId("client");
        s.setScope("scope");
        s.setAuthorizationCode("code");
        s.setResponseUri("https://cb");
        s.setCodeChallenge("challenge");
        s.setCodeChallengeMethod("S256");
        s.setCodeIssuedAt(LocalDateTime.now());
        s.setIsCodeUsed(Boolean.FALSE);
        s.setCodeUsedAt(LocalDateTime.now());
        s.setIdentityData("{}");

        assertEquals("auth", s.getAuthSession());
        assertEquals("txn", s.getTransactionId());
        assertEquals("S256", s.getCodeChallengeMethod());
        assertFalse(s.getIsCodeUsed());

        s.onCreate();
        assertNotNull(s.getCreatedDtimes());
        assertNotNull(s.toString());
        assertNotNull(s.hashCode());
    }

    @Test
    public void renderingTemplate_gettersSetters() {
        RenderingTemplate rt = new RenderingTemplate();
        rt.setId("t1");
        rt.setTemplate("<svg/>");
        LocalDateTime now = LocalDateTime.now();
        rt.setCreatedtimes(now);
        rt.setUpdatedtimes(now);

        assertEquals("t1", rt.getId());
        assertEquals("<svg/>", rt.getTemplate());
        assertEquals(now, rt.getCreatedtimes());

        RenderingTemplate all = new RenderingTemplate("t2", "x", now, now);
        assertEquals("t2", all.getId());
        assertNotEquals(rt, all);
        assertNotNull(rt.toString());
    }

    @Test
    public void credentialConfig_gettersSetters() {
        CredentialConfig cc = new CredentialConfig();
        cc.setConfigId("cfg");
        cc.setStatus("active");
        cc.setVcTemplate("tmpl");
        cc.setCredentialConfigKeyId("key");
        cc.setContext("ctx");
        cc.setCredentialType("MockType");
        cc.setCredentialFormat("ldp_vc");
        cc.setDidUrl("did:web:example");
        cc.setKeyManagerAppId("app");
        cc.setKeyManagerRefId("ref");
        cc.setSignatureAlgo("Ed25519Signature2020");
        cc.setSignatureCryptoSuite("ed25519-rdfc-2022");
        cc.setSdClaim("a,b");
        cc.setDisplay(List.of(new MetaDataDisplay()));
        cc.setOrder(List.of("a"));
        cc.setScope("mock_vc");
        cc.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        cc.setCredentialSigningAlgValuesSupported(List.of("Ed25519Signature2020"));
        cc.setProofTypesSupported(Map.of("jwt", Map.of()));
        cc.setDocType("org.iso.mdl");
        cc.setClaims(Map.of("name", new Claims()));
        cc.setMsoMdocClaims(Map.of("ns", Map.of("f", new Claims())));
        cc.setSdJwtClaims(Map.of("name", new Claims()));
        cc.setSdJwtVct("Vct");
        cc.setPluginConfigurations(List.of(Map.of("k", "v")));
        cc.setCredentialStatusPurposes(List.of("revocation"));
        cc.setQrSettings(List.of(Map.of("k", (Object) "v")));
        cc.setQrSignatureAlgo("RS256");
        cc.setCreatedTimes(LocalDateTime.now());
        cc.setUpdatedTimes(LocalDateTime.now());

        assertEquals("cfg", cc.getConfigId());
        assertEquals("ldp_vc", cc.getCredentialFormat());
        assertEquals("Vct", cc.getSdJwtVct());
        assertEquals(1, cc.getDisplay().size());
        assertEquals(1, cc.getClaims().size());
        assertEquals(List.of("revocation"), cc.getCredentialStatusPurposes());
        assertNotNull(cc.toString());

        CredentialConfig same = new CredentialConfig();
        assertNotEquals(cc, same);
        assertNotNull(cc.hashCode());
    }

    @Test
    public void attributePojos_metaDataDisplayAndNested() {
        MetaDataDisplay.Logo logo = new MetaDataDisplay.Logo("uri", "alt");
        MetaDataDisplay.BackgroundImage bg = new MetaDataDisplay.BackgroundImage("bgUri");
        MetaDataDisplay md = new MetaDataDisplay(logo, "Name", "en", "#000", "#fff", bg);

        assertEquals("uri", md.getLogo().getUri());
        assertEquals("alt", md.getLogo().getAltText());
        assertEquals("bgUri", md.getBackgroundImage().getUri());
        assertEquals("Name", md.getName());
        assertEquals("en", md.getLocale());
        assertEquals("#000", md.getTextColor());
        assertEquals("#fff", md.getBackgroundColor());

        MetaDataDisplay empty = new MetaDataDisplay();
        empty.setName("Other");
        assertNotEquals(md, empty);
        assertNotNull(md.toString());
        assertNotNull(md.hashCode());

        MetaDataDisplay.Logo logo2 = new MetaDataDisplay.Logo();
        logo2.setUri("uri");
        logo2.setAltText("alt");
        assertEquals(logo, logo2);
    }

    @Test
    public void attributePojos_credentialSubjectAndClaims() {
        CredentialSubjectParameters.Display d = new CredentialSubjectParameters.Display("Name", "en");
        CredentialSubjectParameters csp = new CredentialSubjectParameters(List.of(d));
        assertEquals("Name", csp.getDisplay().get(0).getName());
        assertEquals("en", csp.getDisplay().get(0).getLocale());

        CredentialSubjectParameters csp2 = new CredentialSubjectParameters();
        csp2.setDisplay(List.of(new CredentialSubjectParameters.Display("Name", "en")));
        assertEquals(csp, csp2);
        assertNotNull(csp.toString());

        Claims.Display cd = new Claims.Display("N", "fr");
        Claims claims = new Claims(List.of(cd), true);
        assertTrue(claims.isMandatory());
        assertEquals("N", claims.getDisplay().get(0).getName());
        assertNotNull(claims.toString());
        assertNotNull(claims.hashCode());
    }

    @Test
    public void attributePojos_credentialStatusDetail() {
        io.mosip.certify.entity.attributes.CredentialStatusDetail csd =
                new io.mosip.certify.entity.attributes.CredentialStatusDetail(
                        "revocation", Boolean.TRUE, "slc", 7L, 123L);
        assertEquals("revocation", csd.getStatusPurpose());
        assertTrue(csd.getStatusValue());
        assertEquals("slc", csd.getStatusListCredentialId());
        assertEquals(Long.valueOf(7L), csd.getStatusListIndex());
        assertEquals(Long.valueOf(123L), csd.getCreatedTimes());

        io.mosip.certify.entity.attributes.CredentialStatusDetail blank =
                new io.mosip.certify.entity.attributes.CredentialStatusDetail();
        blank.setStatusPurpose("suspension");
        assertNotEquals(csd, blank);
        assertNotNull(csd.toString());
        assertNotNull(csd.hashCode());
    }
}
