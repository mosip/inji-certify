package io.mosip.certify.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.ProblemDetailsTypes;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.dto.VCApiIssueRequest;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.dpop.DpopProofValidator;
import io.mosip.certify.services.VCApiIssuanceService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.MessageSource;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@WebMvcTest(VCApiController.class)
@AutoConfigureMockMvc(addFilters = false)
@TestPropertySource(properties = "mosip.certify.vc-api.enabled=true")
public class VCApiControllerTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private VCApiIssuanceService vcApiIssuanceService;

    @MockBean
    private ParsedAccessToken parsedAccessToken;

    // AccessTokenValidationFilter is a @Component, so the web slice builds it
    // and every collaborator it autowires has to exist here too.
    @MockBean
    private DpopProofValidator dpopProofValidator;

    @MockBean
    private MessageSource messageSource;

    @Test
    public void issueCredential_returnsVerifiableCredential() throws Exception {
        VCApiIssueRequest request = validRequest();

        Map<String, Object> vc = new LinkedHashMap<>();
        vc.put("type", List.of("VerifiableCredential", "FarmerCredential"));
        Mockito.when(vcApiIssuanceService.issue(Mockito.any(), Mockito.eq("my-credential"))).thenReturn(vc);

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .header(VCApiController.CREDENTIAL_CONFIGURATION_ID_HEADER, "my-credential")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.type").isArray());
    }

    @Test
    public void issueCredential_withMissingCredential_thenFail() throws Exception {
        VCApiIssueRequest request = new VCApiIssueRequest();

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .header(VCApiController.CREDENTIAL_CONFIGURATION_ID_HEADER, "my-credential")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.type").value(ProblemDetailsTypes.MALFORMED_VALUE_ERROR))
                .andExpect(jsonPath("$.title").value("Malformed Value Error"))
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.detail").value(VCIErrorConstants.INVALID_REQUEST));
    }

    @Test
    public void issueCredential_withMissingConfigHeader_thenFail() throws Exception {
        mockMvc.perform(post("/vc-api/credentials/issue")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest())))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.type").value(ProblemDetailsTypes.MALFORMED_VALUE_ERROR))
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    public void issueCredential_withBlankConfigHeader_thenFail() throws Exception {
        mockMvc.perform(post("/vc-api/credentials/issue")
                        .header(VCApiController.CREDENTIAL_CONFIGURATION_ID_HEADER, "  ")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest())))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.type").value(ProblemDetailsTypes.MALFORMED_VALUE_ERROR))
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    public void issueCredential_whenServiceThrowsCertifyException_thenFail() throws Exception {
        Mockito.when(vcApiIssuanceService.issue(Mockito.any(), Mockito.eq("unknown-config")))
                .thenThrow(new CertifyException(ErrorConstants.CONFIG_NOT_FOUND_BY_ID, "Config not found"));

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .header(VCApiController.CREDENTIAL_CONFIGURATION_ID_HEADER, "unknown-config")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest())))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.type").value(ProblemDetailsTypes.MALFORMED_VALUE_ERROR))
                .andExpect(jsonPath("$.detail").value("Config not found"))
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    public void issueCredential_whenServiceThrowsUnsupportedFormat_thenFail() throws Exception {
        Mockito.when(vcApiIssuanceService.issue(Mockito.any(), Mockito.eq("sdjwt-config")))
                .thenThrow(new CertifyException(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT,
                        "VC API supports only ldp_vc credential format"));

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .header(VCApiController.CREDENTIAL_CONFIGURATION_ID_HEADER, "sdjwt-config")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest())))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.type").value(ProblemDetailsTypes.MALFORMED_VALUE_ERROR))
                .andExpect(jsonPath("$.detail").value("VC API supports only ldp_vc credential format"))
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    public void issueCredential_whenMalformedJson_thenFail() throws Exception {
        mockMvc.perform(post("/vc-api/credentials/issue")
                        .header(VCApiController.CREDENTIAL_CONFIGURATION_ID_HEADER, "my-credential")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{not-json"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.type").value(ProblemDetailsTypes.PARSING_ERROR))
                .andExpect(jsonPath("$.title").value("Parsing Error"))
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    public void issueCredential_whenIssuanceFails_thenInternalServerError() throws Exception {
        Mockito.when(vcApiIssuanceService.issue(Mockito.any(), Mockito.eq("my-credential")))
                .thenThrow(new CertifyException(ErrorConstants.VC_ISSUANCE_FAILED, "Credential signing failed"));

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .header(VCApiController.CREDENTIAL_CONFIGURATION_ID_HEADER, "my-credential")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest())))
                .andExpect(status().isInternalServerError())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.type").value(ProblemDetailsTypes.ABOUT_BLANK))
                .andExpect(jsonPath("$.title").value("Internal Server Error"))
                .andExpect(jsonPath("$.detail").value("Credential signing failed"))
                .andExpect(jsonPath("$.status").value(500));
    }

    @Test
    public void issueCredential_whenStatusListIndexUnavailable_thenInternalServerError() throws Exception {
        Mockito.when(vcApiIssuanceService.issue(Mockito.any(), Mockito.eq("my-credential")))
                .thenThrow(new CertifyException(ErrorConstants.STATUS_LIST_INDEX_UNAVAILABLE,
                        "Error fetching available index from status list"));

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .header(VCApiController.CREDENTIAL_CONFIGURATION_ID_HEADER, "my-credential")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest())))
                .andExpect(status().isInternalServerError())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.type").value(ProblemDetailsTypes.ABOUT_BLANK))
                .andExpect(jsonPath("$.title").value("Internal Server Error"))
                .andExpect(jsonPath("$.status").value(500));
    }

    @Test
    public void issueCredential_whenUnhandledException_thenDoesNotExposeExceptionMessage() throws Exception {
        Mockito.when(vcApiIssuanceService.issue(Mockito.any(), Mockito.eq("my-credential")))
                .thenThrow(new RuntimeException("duplicate key for Jane Doe at /var/lib/postgresql"));

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .header(VCApiController.CREDENTIAL_CONFIGURATION_ID_HEADER, "my-credential")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest())))
                .andExpect(status().isInternalServerError())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.type").value(ProblemDetailsTypes.ABOUT_BLANK))
                .andExpect(jsonPath("$.title").value("Internal Server Error"))
                .andExpect(jsonPath("$.detail").value("Internal Server Error"))
                .andExpect(jsonPath("$.status").value(500));
    }

    @Test
    public void issueCredential_whenUnsupportedOptions_thenFail() throws Exception {
        Mockito.when(vcApiIssuanceService.issue(Mockito.any(), Mockito.eq("my-credential")))
                .thenThrow(new CertifyException(ErrorConstants.UNKNOWN_OPTION_PROVIDED,
                        "VC API issue options proof hints are not supported; omit options or pass an empty object"));

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .header(VCApiController.CREDENTIAL_CONFIGURATION_ID_HEADER, "my-credential")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest())))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.type").value(ProblemDetailsTypes.UNKNOWN_OPTION_PROVIDED))
                .andExpect(jsonPath("$.title").value("Unknown Option Provided"))
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    public void issueCredential_whenValidUntilNotAfterValidFrom_thenRangeError() throws Exception {
        Mockito.when(vcApiIssuanceService.issue(Mockito.any(), Mockito.eq("my-credential")))
                .thenThrow(new CertifyException(ErrorConstants.INVALID_EXPIRY_RANGE,
                        "validUntil must be later than validFrom"));

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .header(VCApiController.CREDENTIAL_CONFIGURATION_ID_HEADER, "my-credential")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest())))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.type").value(ProblemDetailsTypes.RANGE_ERROR))
                .andExpect(jsonPath("$.title").value("Range Error"))
                .andExpect(jsonPath("$.status").value(400));
    }

    private VCApiIssueRequest validRequest() {
        VCApiIssueRequest request = new VCApiIssueRequest();
        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("@context", List.of(VCDM2Constants.URL));
        credential.put("type", List.of("VerifiableCredential", "FarmerCredential"));
        credential.put("issuer", "did:web:example.issuer");
        credential.put("validFrom", "2026-01-01T00:00:00.000Z");
        credential.put("credentialSubject", Map.of("id", "did:example:holder", "fullName", "Jane Doe"));
        request.setCredential(credential);
        return request;
    }
}
