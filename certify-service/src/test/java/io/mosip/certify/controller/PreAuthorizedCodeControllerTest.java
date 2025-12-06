package io.mosip.certify.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.core.dto.PreAuthorizedRequest;
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

import java.util.HashMap;
import java.util.Map;

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
    public void generatePreAuthorizedCode_MissingConfigId_Fail() throws Exception {
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
    public void generatePreAuthorizedCode_MissingClaims_Fail() throws Exception {
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
}
