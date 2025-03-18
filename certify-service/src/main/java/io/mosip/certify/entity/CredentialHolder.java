package io.mosip.certify.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "credential_holder")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CredentialHolder {
    @Id
    @Column(name = "id", nullable = false, unique = true)
    private String id;
    
    @Column(name = "credential_id", nullable = false, unique = true)
    private String credentialId;
    
    @Column(name = "holder_id")
    private String holderId;
    
    @Lob
    @Column(name = "encrypted_holder_name")
    private byte[] encryptedHolderName;
    
    @Lob
    @Column(name = "encrypted_holder_email")
    private byte[] encryptedHolderEmail;
    
    @Lob
    @Column(name = "encrypted_holder_address")
    private byte[] encryptedHolderAddress;
    
    @Column(name = "credential_type", nullable = false)
    private String credentialType;
    
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt = LocalDateTime.now();
    
    @Column(name = "cr_by", nullable = false)
    private String createdBy;
    
    @Column(name = "cr_dtimes", nullable = false)
    private LocalDateTime createdTimes;
    
    @Column(name = "upd_by")
    private String updatedBy;
    
    @Column(name = "upd_dtimes")
    private LocalDateTime updatedTimes;
    
    @Column(name = "is_deleted", columnDefinition = "BOOLEAN DEFAULT FALSE")
    private Boolean isDeleted;
    
    @Column(name = "del_dtimes")
    private LocalDateTime deletedTimes;
    
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "credential_id", referencedColumnName = "credential_id", insertable = false, updatable = false)
    private CredentialStatus credentialStatus;
}