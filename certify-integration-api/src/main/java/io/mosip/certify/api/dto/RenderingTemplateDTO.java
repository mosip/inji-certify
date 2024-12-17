package io.mosip.certify.api.dto;

import lombok.Data;

import java.time.LocalDateTime;

@Data
public class RenderingTemplateDTO {
    private String id;
    private String template;
    private LocalDateTime createdTimes;
    private LocalDateTime updatedTimes;
}
