package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import java.util.List;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
@Data
public class CredentialConfigurationSupported {

    private String id;
    private String format;
    private String scope;
    private List<String> types;
    private Map<String, Object> proofTypesSupported;
    private List<String> cryptographicBindingMethodsSupported;
    private List<String> context;
    private String vct;
    private String docType;

}
