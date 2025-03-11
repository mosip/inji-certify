package io.mosip.certify.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Entity
@Table(name="credential_config")
public class CredentialConfig {
    @Id
    private String id;

    private String status;

    private String configuration;

    @NotNull
    @Column(name = "cr_dtimes")
    private LocalDateTime createdTime;

    @Column(name = "upd_dtimes")
    private LocalDateTime updatedTime;
}
