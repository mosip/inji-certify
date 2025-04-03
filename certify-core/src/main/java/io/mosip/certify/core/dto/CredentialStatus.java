package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@Data
public class CredentialStatus {
    private String id;
    private String type;
    private String statusPurpose;
    private Long statusListIndex;
    private String statusListCredential;
}
