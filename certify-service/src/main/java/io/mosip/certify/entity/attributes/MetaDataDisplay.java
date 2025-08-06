package io.mosip.certify.entity.attributes;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MetaDataDisplay implements Serializable {
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
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Logo implements Serializable {
        private String url;

        @JsonProperty("alt_text")
        private String altText;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class BackgroundImage {
        private String uri;
    }
}
