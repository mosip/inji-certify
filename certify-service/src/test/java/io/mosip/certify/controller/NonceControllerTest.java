package io.mosip.certify.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.dto.NonceResponse;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.dpop.DpopProofValidator;
import io.mosip.certify.core.spi.NonceService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@RunWith(SpringRunner.class)
@WebMvcTest(NonceController.class)
public class NonceControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private NonceService nonceService;

    @MockBean
    ParsedAccessToken parsedAccessToken;

    // AccessTokenValidationFilter is a @Component, so the web slice builds it
    // and every collaborator it autowires has to exist here too.
    @MockBean
    DpopProofValidator dpopProofValidator;

    @Test
    public void testGetNonce_success() throws Exception {

        // Arrange
        NonceResponse mockResponse = new NonceResponse("test-nonce-123");

        Mockito.when(nonceService.generateNonce()).thenReturn(mockResponse);

        // Act & Assert
        mockMvc.perform(post("/nonce")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.c_nonce").value("test-nonce-123"));
    }
}