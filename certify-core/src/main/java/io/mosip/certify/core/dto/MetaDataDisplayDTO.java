package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class MetaDataDisplayDTO {
    private Logo logo;
    private String name;
    private String locale;

    @JsonProperty("text_color")
    private String textColor;

    @JsonProperty("background_color")
    private String backgroundColor;

    @JsonProperty("background_image")
    private BackgroundImage backgroundImage;

    @Data
    public static class Logo {
        private String url;

        @JsonProperty("alt_text")
        private String altText;
    }

    @Data
    public static class BackgroundImage {
        private String uri;
    }
}
