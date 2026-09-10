package io.mosip.certify.controller;

import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequest;
import io.mosip.certify.core.spi.CredentialStatusService;
import io.mosip.certify.services.StatusListCredentialService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class CredentialStatusControllerTest {

    @Mock
    private StatusListCredentialService statusListCredentialService;
    @Mock
    private CredentialStatusService credentialStatusService;
    @InjectMocks
    private CredentialStatusController controller;

    @Test
    public void getStatusListById_returnsDocument() {
        when(statusListCredentialService.getStatusListCredential("id-1")).thenReturn("{\"vc\":true}");
        assertEquals("{\"vc\":true}", controller.getStatusListById("id-1"));
    }

    @Test
    public void updateCredential_withResult_returnsOk() {
        UpdateCredentialStatusRequest request = new UpdateCredentialStatusRequest();
        CredentialStatusResponse response = new CredentialStatusResponse();
        when(credentialStatusService.updateCredentialStatus(request)).thenReturn(response);

        ResponseEntity<CredentialStatusResponse> result = controller.updateCredential(request);
        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertEquals(response, result.getBody());
    }

    @Test
    public void updateCredential_nullResult_returnsNoContent() {
        UpdateCredentialStatusRequest request = new UpdateCredentialStatusRequest();
        when(credentialStatusService.updateCredentialStatus(request)).thenReturn(null);

        ResponseEntity<CredentialStatusResponse> result = controller.updateCredential(request);
        assertEquals(HttpStatus.NO_CONTENT, result.getStatusCode());
    }
}
