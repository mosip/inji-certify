package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@JsonIgnoreProperties(ignoreUnknown = true)
@Data
public class SvgRenderTemplateDto {
    private UUID id;
    private String svgTemplate;
    private LocalDateTime lastModified;
}
