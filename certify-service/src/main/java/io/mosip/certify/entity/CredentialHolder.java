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
    
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "credential_id", referencedColumnName = "credential_id", insertable = false, updatable = false)
    private LedgerIssuanceTable ledgerIssuanceTable;
}