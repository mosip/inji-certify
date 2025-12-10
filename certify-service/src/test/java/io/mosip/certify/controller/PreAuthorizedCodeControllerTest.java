package io.mosip.certify.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.core.dto.CredentialOfferResponse;
import io.mosip.certify.core.dto.PreAuthorizedRequest;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.services.PreAuthorizedCodeService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@WebMvcTest(value = PreAuthorizedCodeController.class)
public class PreAuthorizedCodeControllerTest {

    @Autowired
    MockMvc mockMvc;

    @MockBean
    PreAuthorizedCodeService preAuthorizedCodeService;

    // Required by AccessTokenValidationFilter which is loaded in WebMvcTest context
    @MockBean
    io.mosip.certify.core.dto.ParsedAccessToken parsedAccessToken;

    // Required by audit aspects/configuration
    @MockBean
    AuditPlugin auditWrapper;

    ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void generatePreAuthorizedCode_Success() throws Exception {
        PreAuthorizedRequest request = new PreAuthorizedRequest();
        request.setCredentialConfigurationId("test-config");
        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "John");
        request.setClaims(claims);

        String expectedUri = "openid-credential-offer://?credential_offer_uri=test";
        Mockito.when(preAuthorizedCodeService.generatePreAuthorizedCode(Mockito.any(PreAuthorizedRequest.class)))
                .thenReturn(expectedUri);

        mockMvc.perform(post("/pre-authorized-data")
                .content(objectMapper.writeValueAsBytes(request))
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credential_offer_uri").value(expectedUri));
    }

    @Test
    public void generatePreAuthorizedCode_Failure_If_MissingConfigId() throws Exception {
        PreAuthorizedRequest request = new PreAuthorizedRequest();
        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "John");
        request.setClaims(claims);
        // Missing credentialConfigurationId

        mockMvc.perform(post("/pre-authorized-data")
                .content(objectMapper.writeValueAsBytes(request))
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk()) // ExceptionHandler returns 200 OK with errors
                .andExpect(jsonPath("$.errors").isArray())
                .andExpect(jsonPath("$.errors[0].errorCode").value("Credential configuration ID is required"));
    }

    @Test
    public void generatePreAuthorizedCode_Failure_If_MissingClaims() throws Exception {
        PreAuthorizedRequest request = new PreAuthorizedRequest();
        request.setCredentialConfigurationId("test-config");
        // Missing claims

        mockMvc.perform(post("/pre-authorized-data")
                .content(objectMapper.writeValueAsBytes(request))
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk()) // ExceptionHandler returns 200 OK with errors
                .andExpect(jsonPath("$.errors").isArray())
                .andExpect(jsonPath("$.errors[0].errorCode").value("Claims are required"));
    }

    @Test
    public void getCredentialOffer_Success() throws Exception {
        String validUuid = "550e8400-e29b-41d4-a716-446655440000";
        CredentialOfferResponse offer = CredentialOfferResponse.builder()
                .credentialIssuer("https://issuer.com")
                .credentialConfigurationIds(Collections.singletonList("test-config"))
                .build();

        Mockito.when(preAuthorizedCodeService.getCredentialOffer(validUuid))
                .thenReturn(offer);

        mockMvc.perform(get("/credential-offer-data/{offer_id}", validUuid)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credential_issuer").value("https://issuer.com"))
                .andExpect(jsonPath("$.credential_configuration_ids[0]").value("test-config"));
    }

    @Test
    public void getCredentialOffer_InvalidUuidFormat() throws Exception {
        String invalidUuid = "not-a-valid-uuid";

        Mockito.when(preAuthorizedCodeService.getCredentialOffer(invalidUuid))
                .thenThrow(new InvalidRequestException(ErrorConstants.INVALID_OFFER_ID_FORMAT));

        mockMvc.perform(get("/credential-offer-data/{offer_id}", invalidUuid)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk()) // ExceptionHandler returns 200 OK with errors
                .andExpect(jsonPath("$.errors").isArray())
                .andExpect(jsonPath("$.errors[0].errorCode").value(ErrorConstants.INVALID_OFFER_ID_FORMAT));
    }

    @Test
    public void getCredentialOffer_NotFound() throws Exception {
        String validUuid = "550e8400-e29b-41d4-a716-446655440000";

        Mockito.when(preAuthorizedCodeService.getCredentialOffer(validUuid))
                .thenThrow(new CertifyException("offer_not_found", "Credential offer not found or expired"));

        mockMvc.perform(get("/credential-offer-data/{offer_id}", validUuid)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk()) // ExceptionHandler returns 200 OK with errors
                .andExpect(jsonPath("$.errors").isArray())
                .andExpect(jsonPath("$.errors[0].errorCode").value("offer_not_found"));
    }
}
