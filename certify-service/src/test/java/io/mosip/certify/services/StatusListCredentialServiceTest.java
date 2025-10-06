package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.credential.Credential;
import io.mosip.certify.credential.CredentialFactory;
import io.mosip.certify.credential.W3CJsonLD;
import io.mosip.certify.entity.Ledger;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.entity.attributes.CredentialStatusDetail;
import io.mosip.certify.repository.LedgerRepository;
import io.mosip.certify.repository.StatusListAvailableIndicesRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import org.json.JSONObject;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;

import java.time.LocalDateTime;
import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class StatusListCredentialServiceTest {

    @InjectMocks
    private StatusListCredentialService service;

    @Mock
    private StatusListCredentialRepository statusListCredentialRepository;
    @Mock
    private CredentialFactory credentialFactory;
    @Mock
    private LedgerRepository ledgerRepository;
    @Mock
    private StatusListAvailableIndicesRepository statusListAvailableIndicesRepository;
    @Mock
    private DatabaseStatusListIndexProvider indexProvider;
    @Mock
    private EntityManager entityManager;
    @Mock
    private Credential credential;

    @Before
    public void setUp() {
        ReflectionTestUtils.setField(service, "statusListCredentialRepository", statusListCredentialRepository);
        ReflectionTestUtils.setField(service, "credentialFactory", credentialFactory);
        ReflectionTestUtils.setField(service, "ledgerRepository", ledgerRepository);
        ReflectionTestUtils.setField(service, "indexProvider", indexProvider);
        ReflectionTestUtils.setField(service, "entityManager", entityManager);
        ReflectionTestUtils.setField(service, "didUrl", "did:example:issuer");
        ReflectionTestUtils.setField(service, "domainUrl", "https://example.com");
        ReflectionTestUtils.setField(service, "statusListSizeInKB", 2L);
        ReflectionTestUtils.setField(service, "signatureCryptoSuite", "Ed25519Signature2020");
        ReflectionTestUtils.setField(service, "signatureAlgo", "EdDSA");
        ReflectionTestUtils.setField(service, "statusListKeyManagerRefId", "ED25519_SIGN");
        Map<String, List<List<String>>> keyAliasMapper = new HashMap<>();
        keyAliasMapper.put("Ed25519Signature2020", Arrays.asList(Arrays.asList("appId")));
        ReflectionTestUtils.setField(service, "keyAliasMapper", keyAliasMapper);
    }

    @Test
    public void getStatusListCredential_ReturnsVC() {
        StatusListCredential slc = new StatusListCredential();
        slc.setId("id1");
        slc.setVcDocument("{\"foo\":\"bar\"}");
        when(statusListCredentialRepository.findById("id1")).thenReturn(Optional.of(slc));
        String result = service.getStatusListCredential("id1");
        assertTrue(result.contains("foo"));
    }

    @Test
    public void getStatusListCredential_NotFound_Throws() {
        when(statusListCredentialRepository.findById("id2")).thenReturn(Optional.empty());
        try {
            service.getStatusListCredential("id2");
            fail("Expected CertifyException");
        } catch (CertifyException ex) {
            assertEquals(ErrorConstants.STATUS_LIST_NOT_FOUND, ex.getErrorCode());
        }
    }

    @Test
    public void getStatusListCredential_JsonError_Throws() {
        StatusListCredential slc = new StatusListCredential();
        slc.setId("id3");
        slc.setVcDocument("not-json");
        when(statusListCredentialRepository.findById("id3")).thenReturn(Optional.of(slc));
        try {
            service.getStatusListCredential("id3");
            fail("Expected CertifyException");
        } catch (CertifyException ex) {
            // expected
        }
    }

    @Test
    public void findStatusListById_ReturnsOptional() {
        StatusListCredential slc = new StatusListCredential();
        slc.setId("id4");
        when(statusListCredentialRepository.findById("id4")).thenReturn(Optional.of(slc));
        Optional<StatusListCredential> result = service.findStatusListById("id4");
        assertTrue(result.isPresent());
    }

    @Test
    public void findStatusListById_Exception_ReturnsEmpty() {
        when(statusListCredentialRepository.findById("id5")).thenThrow(new RuntimeException("db error"));
        Optional<StatusListCredential> result = service.findStatusListById("id5");
        assertFalse(result.isPresent());
    }

    @Test
    public void generateStatusListCredential_Success() {
        W3CJsonLD w3CJsonLD = mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(w3CJsonLD));
        VCResult mockVcResultLdp = new VCResult<JsonLDObject>();
        JsonLDObject signedCredObj = JsonLDObject.fromJson("{\"signed\":\"credential\", \"proof\":{}}");
        mockVcResultLdp.setCredential(signedCredObj);

        when(w3CJsonLD.addProof(
                anyString(),
                eq(""),
                anyString(),
                anyString(),
                anyString(),
                anyString(),
                anyString()
        )).thenReturn(mockVcResultLdp);
        when(statusListCredentialRepository.saveAndFlush(any())).thenAnswer(i -> i.getArgument(0));
        // Mock entityManager for initializeAvailableIndices
        Query mockQuery = mock(Query.class);
        when(entityManager.createNativeQuery(anyString())).thenReturn(mockQuery);
        when(mockQuery.setParameter(anyInt(), any())).thenReturn(mockQuery);
        when(mockQuery.getSingleResult()).thenReturn(1L);
        when(mockQuery.executeUpdate()).thenReturn(2);

        StatusListCredential result = service.generateStatusListCredential("revocation");
        assertEquals("revocation", result.getStatusPurpose());
    }

    @Test
    public void generateStatusListCredential_JsonError_Throws() {
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(credential));
        when(credential.addProof(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenThrow(new RuntimeException("json error"));
        try {
            service.generateStatusListCredential("revocation");
            fail("Expected CertifyException");
        } catch (CertifyException ex) {
            // expected
        }
    }

    @Test
    public void findOrCreateStatusList_FindsExisting() {
        StatusListCredential slc = new StatusListCredential();
        slc.setId("id6");
        when(statusListCredentialRepository.findSuitableStatusList(anyString(), any())).thenReturn(Optional.of(slc));
        StatusListCredential result = service.findOrCreateStatusList("revocation");
        assertEquals("id6", result.getId());
    }

    @Test
    public void findOrCreateStatusList_CreatesNew() {
        when(statusListCredentialRepository.findSuitableStatusList(anyString(), any())).thenReturn(Optional.empty());
        W3CJsonLD w3CJsonLD = mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(w3CJsonLD));
        VCResult mockVcResultLdp = new VCResult<JsonLDObject>();
        JsonLDObject signedCredObj = JsonLDObject.fromJson("{\"signed\":\"credential\", \"proof\":{}}");
        mockVcResultLdp.setCredential(signedCredObj);

        when(w3CJsonLD.addProof(
                anyString(),
                eq(""),
                anyString(),
                anyString(),
                anyString(),
                anyString(),
                anyString()
        )).thenReturn(mockVcResultLdp);
        when(statusListCredentialRepository.saveAndFlush(any())).thenAnswer(i -> i.getArgument(0));

        // Mock entityManager for initializeAvailableIndices
        Query mockQuery = mock(Query.class);
        when(entityManager.createNativeQuery(anyString())).thenReturn(mockQuery);
        when(mockQuery.setParameter(anyInt(), any())).thenReturn(mockQuery);
        when(mockQuery.getSingleResult()).thenReturn(1L);
        when(mockQuery.executeUpdate()).thenReturn(2);

        StatusListCredential result = service.findOrCreateStatusList("revocation");
        assertEquals("revocation", result.getStatusPurpose());
        assertNotNull(result.getId());
    }

    @Test
    public void findNextAvailableIndex_ReturnsIndex() {
        when(indexProvider.acquireIndex(anyString(), anyMap())).thenReturn(Optional.of(42L));
        long idx = service.findNextAvailableIndex("slid");
        assertEquals(42L, idx);
    }

    @Test
    public void findNextAvailableIndex_None_ReturnsMinus1() {
        when(indexProvider.acquireIndex(anyString(), anyMap())).thenReturn(Optional.empty());
        long idx = service.findNextAvailableIndex("slid");
        assertEquals(-1L, idx);
    }

    @Test
    public void resignStatusListCredential_Success() {
        W3CJsonLD w3CJsonLD = mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(w3CJsonLD));
        VCResult mockVcResultLdp = new VCResult<JsonLDObject>();
        JsonLDObject signedCredObj = JsonLDObject.fromJson("{\"signed\":\"credential\", \"proof\":{}}");
        mockVcResultLdp.setCredential(signedCredObj);

        // The holderId argument to addProof in the service is "" for LDP
        when(w3CJsonLD.addProof(
                anyString(),
                eq(""),  // Service code passes "" for LDP's addProof holderId
                anyString(),
                anyString(),
                anyString(),
                anyString(),
                anyString()
        )).thenReturn(mockVcResultLdp);
        String input = "{\"unsigned\":\"credential\"}";
        String result = service.resignStatusListCredential(input);
        assertNotNull(result);
    }

    @Test
    public void resignStatusListCredential_Error_Throws() {
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(credential));
        when(credential.addProof(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenThrow(new RuntimeException("fail"));
        try {
            service.resignStatusListCredential("{\"foo\":\"bar\"}");
            fail("Expected CertifyException");
        } catch (CertifyException ex) {
            // expected
        }
    }

    @Test
    public void addCredentialStatus_AssignsIndexAndSetsDetail() {
        StatusListCredential slc = new StatusListCredential();
        slc.setId("slid");
        slc.setStatusPurpose("revocation");
        when(statusListCredentialRepository.findSuitableStatusList(anyString(), any())).thenReturn(Optional.of(slc));
        when(indexProvider.acquireIndex(anyString(), anyMap())).thenReturn(Optional.of(1L));
        JSONObject json = new JSONObject();
        service.addCredentialStatus(json, "revocation");
        assertTrue(json.has(VCDM2Constants.CREDENTIAL_STATUS));
    }

    @Test
    public void addCredentialStatus_ListFull_CreatesNew() {
        StatusListCredential slc = new StatusListCredential();
        slc.setId("slid");
        slc.setStatusPurpose("revocation");
        when(statusListCredentialRepository.findSuitableStatusList(anyString(), any())).thenReturn(Optional.of(slc));
        when(indexProvider.acquireIndex(anyString(), anyMap())).thenReturn(Optional.of(-1L)).thenReturn(Optional.of(2L));
        W3CJsonLD w3CJsonLD = mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(w3CJsonLD));
        VCResult mockVcResultLdp = new VCResult<JsonLDObject>();
        JsonLDObject signedCredObj = JsonLDObject.fromJson("{\"signed\":\"credential\", \"proof\":{}}");
        mockVcResultLdp.setCredential(signedCredObj);

        when(w3CJsonLD.addProof(
                anyString(),
                eq(""),
                anyString(),
                anyString(),
                anyString(),
                anyString(),
                anyString()
        )).thenReturn(mockVcResultLdp);
        when(statusListCredentialRepository.saveAndFlush(any())).thenAnswer(i -> i.getArgument(0));

        // Mock entityManager for initializeAvailableIndices
        Query mockQuery = mock(Query.class);
        when(entityManager.createNativeQuery(anyString())).thenReturn(mockQuery);
        when(mockQuery.setParameter(anyInt(), any())).thenReturn(mockQuery);
        when(mockQuery.getSingleResult()).thenReturn(1L);
        when(mockQuery.executeUpdate()).thenReturn(2);

        JSONObject json = new JSONObject();
        service.addCredentialStatus(json, "revocation");
        assertTrue(json.has(VCDM2Constants.CREDENTIAL_STATUS));
    }

    @Test
    public void addCredentialStatus_ListFullAndStillNoIndex_Throws() {
        StatusListCredential slc = new StatusListCredential();
        slc.setId("slid");
        slc.setStatusPurpose("revocation");
        when(statusListCredentialRepository.findSuitableStatusList(anyString(), any())).thenReturn(Optional.of(slc));
        when(indexProvider.acquireIndex(anyString(), anyMap())).thenReturn(Optional.of(-1L)).thenReturn(Optional.of(-1L));
        W3CJsonLD w3CJsonLD = mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(w3CJsonLD));
        VCResult mockVcResultLdp = new VCResult<JsonLDObject>();
        JsonLDObject signedCredObj = JsonLDObject.fromJson("{\"signed\":\"credential\", \"proof\":{}}");
        mockVcResultLdp.setCredential(signedCredObj);

        JSONObject json = new JSONObject();
        CredentialStatusDetail detail = new CredentialStatusDetail();
        try {
            service.addCredentialStatus(json, "revocation");
            fail("Expected CertifyException");
        } catch (CertifyException ex) {
            // expected
        }
    }

    @Test
    public void storeLedgerEntry_Success() {
        CredentialStatusDetail detail = new CredentialStatusDetail();
        Map<String, Object> attrs = Collections.singletonMap("foo", "bar");
        service.storeLedgerEntry("cid", "issuer", "ctype", detail, attrs, LocalDateTime.now());
        verify(ledgerRepository).save(any(Ledger.class));
    }

    @Test
    public void storeLedgerEntry_Error_Throws() {
        doThrow(new RuntimeException("fail")).when(ledgerRepository).save(any());
        try {
            service.storeLedgerEntry("cid", "issuer", "ctype", new CredentialStatusDetail(), Collections.emptyMap(), LocalDateTime.now());
            fail("Expected RuntimeException");
        } catch (RuntimeException ex) {
            // expected
        }
    }
}