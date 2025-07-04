package io.mosip.certify.core.dto;

import lombok.Data;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonFormat;

@Data
public class CredentialStatusResponse {
    private String credentialId;
    private String issuerId;
    private String statusListCredentialUrl;
    private Long statusListIndex;
    private String statusPurpose;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime issueDate;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime expirationDate;
    
    private String credentialType;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime statusTimestamp;

    private List<Map<String, Object>> credentialStatusDetails;
}