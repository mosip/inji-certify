package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class CredentialDisplayConfigDTO {
    private Logo logo;
    private String name;
    private String locale;

    @JsonProperty("text_color")
    private String textColor;

    @JsonProperty("background_color")
    private String backgroundColor;

    @Data
    public static class Logo {
        private String url;

        @JsonProperty("alt_text")
        private String altText;
    }
}
