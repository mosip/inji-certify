package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.time.LocalDateTime;

@JsonIgnoreProperties(ignoreUnknown = true)
@Data
public class SvgRenderTemplateDto {
    private String id;
    private String svgTemplate;
    private LocalDateTime lastModified;
}
