package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@Data
public class CredentialMetadata {

    private String id;
    private String format;
    private String scope;
    private List<String> proof_types_supported;
    private List<String> types;

}
