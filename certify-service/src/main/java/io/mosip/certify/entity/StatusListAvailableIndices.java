package io.mosip.certify.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "status_list_available_indices",
        uniqueConstraints = {
                @UniqueConstraint(name = "uq_list_id_and_index",
                        columnNames = {"status_list_credential_id", "list_index"})
        },
        indexes = {
                @Index(name = "idx_sla_available_indices",
                        columnList = "status_list_credential_id, is_assigned, list_index")
        }
)
@Data
@NoArgsConstructor
@AllArgsConstructor
public class StatusListAvailableIndices {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "status_list_credential_id", length = 255, nullable = false)
    private String statusListCredentialId;

    @Column(name = "list_index", nullable = false)
    private Long listIndex;

    @Column(name = "is_assigned", nullable = false)
    private Boolean isAssigned = false;

    @Column(name = "cr_dtimes", nullable = false, updatable = false)
    private LocalDateTime createdDtimes;

    @Column(name = "upd_dtimes")
    private LocalDateTime updatedDtimes;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "status_list_credential_id",
            foreignKey = @ForeignKey(name = "fk_status_list_credential"),
            insertable = false, updatable = false)
    private StatusListCredential statusListCredential;

    @PrePersist
    protected void onCreate() {
        createdDtimes = LocalDateTime.now();
        if (isAssigned == null) {
            isAssigned = false;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        updatedDtimes = LocalDateTime.now();
    }
}