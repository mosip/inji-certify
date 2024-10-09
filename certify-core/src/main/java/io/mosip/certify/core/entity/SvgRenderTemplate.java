package io.mosip.certify.core.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
public class SvgRenderTemplate {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @NotBlank(message = "Template should not be empty")
    @Column(name = "svg_template")
    private String svgTemplate;

    @NotBlank(message = "Last modified value should not be empty")
    @Column(name = "last_modified")
    private LocalDateTime lastModified;
}
