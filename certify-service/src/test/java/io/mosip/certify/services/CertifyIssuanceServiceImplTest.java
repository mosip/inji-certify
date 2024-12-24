package io.mosip.certify.services;

import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.CredentialDefinition;
import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.exception.NotAuthenticatedException;
import io.mosip.certify.core.util.SecurityHelperService;
import io.mosip.certify.proof.ProofValidatorFactory;
import io.mosip.certify.vcsigners.VCSigner;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.Assert.*;

@RunWith(MockitoJUnitRunner.class)
public class CertifyIssuanceServiceImplTest {

    @Mock
    private LinkedHashMap<String, LinkedHashMap<String, Object>> issuerMetadata;

    @Mock
    private ParsedAccessToken parsedAccessToken;

    @Mock
    private VCFormatter vcFormatter;

    @Mock
    private VCSigner vcSigner;

    @Mock
    private DataProviderPlugin dataProviderPlugin;

    @Mock
    private ProofValidatorFactory proofValidatorFactory;

    @Mock
    private VCICacheService vciCacheService;

    @Mock
    private SecurityHelperService securityHelperService;

    @Mock
    private AuditPlugin auditWrapper;

    @InjectMocks
    private CertifyIssuanceServiceImpl issuanceService;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }
    @Test
    public void getCredentialIssuerMetadata_valid() {
        Mockito.when(issuerMetadata.containsKey("latest")).thenReturn(true);
        Mockito.when(issuerMetadata.get("latest")).thenReturn((new LinkedHashMap()));
        Map<String, Object> actual = issuanceService.getCredentialIssuerMetadata("latest");
        assertNotNull(actual);
    }

    @Test
    public void getCredentialIssuerMetadataVD11_valid() {
        Mockito.when(issuerMetadata.containsKey("vd11")).thenReturn(false);
        LinkedHashMap<String, Object> linkedHashMap = new LinkedHashMap<>();
        linkedHashMap.put("credential_issuer", "https://localhost:9090");
        linkedHashMap.put("credential_endpoint", "https://localhost:9090/v1/certify/issuance/credential");
        Mockito.when(issuerMetadata.get("latest")).thenReturn(linkedHashMap);
        Map<String, Object> actual = issuanceService.getCredentialIssuerMetadata("vd11");
        assertNotNull(actual);
        assertTrue(actual.containsKey("credential_issuer"));
        assertTrue(actual.containsKey("credential_endpoint"));
        assertEquals("https://localhost:9090/v1/certify/issuance/vd11/credential", actual.get("credential_endpoint"));
    }

    @Test
    public void getCredentialIssuerMetadataVD12_valid() {
        Mockito.when(issuerMetadata.containsKey("vd12")).thenReturn(false);
        LinkedHashMap<String, Object> linkedHashMap = new LinkedHashMap<>();
        linkedHashMap.put("credential_issuer", "https://localhost:9090");
        linkedHashMap.put("credential_endpoint", "https://localhost:9090/v1/certify/issuance/credential");
        Mockito.when(issuerMetadata.get("latest")).thenReturn(linkedHashMap);
        Map<String, Object> actual = issuanceService.getCredentialIssuerMetadata("vd12");
        assertNotNull(actual);
        assertTrue(actual.containsKey("credential_issuer"));
        assertTrue(actual.containsKey("credential_endpoint"));
        assertEquals("https://localhost:9090/v1/certify/issuance/vd12/credential", actual.get("credential_endpoint"));
    }

    @Test
    public void getCredentialIssuerMetadata_invalid() {
        Mockito.when(issuerMetadata.containsKey("latest")).thenReturn(false);
        assertThrows(InvalidRequestException.class, () -> issuanceService.getCredentialIssuerMetadata("latest"));
        assertThrows(ErrorConstants.UNSUPPORTED_OPENID_VERSION, InvalidRequestException.class, () -> issuanceService.getCredentialIssuerMetadata(null));
    }

    @Test
    public void getVerifiableCredential_invalidRequest() {
        CredentialRequest cr = new CredentialRequest();
        cr.setFormat("fake-format");
        assertThrows(ErrorConstants.INVALID_REQUEST, InvalidRequestException.class,
                () -> issuanceService.getCredential(cr));
    }

    @Test
    public void getVerifiableCredential_invalidScope() {
        CredentialRequest cr = new CredentialRequest();
        cr.setFormat(VCFormats.LDP_VC);
        cr.setCredential_definition(new CredentialDefinition());
        Mockito.when(parsedAccessToken.isActive()).thenReturn(false);
        assertThrows(NotAuthenticatedException.class, () -> issuanceService.getCredential(cr));
    }
}