package io.mosip.certify.repository;

import io.mosip.certify.entity.Ledger;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface LedgerRepository extends JpaRepository<Ledger, Long>, LedgerIssuanceTableCustomRepository {
    Optional<Ledger> findByCredentialId(String credentialId);

    @Query(value = "SELECT * FROM ledger l " +
            "WHERE l.credential_status_details @> " +
            "jsonb_build_array(" +
            "jsonb_build_object('status_list_credential_id', :statusListCredential, 'status_list_index', :statusListIndex)" +
            ")",
            nativeQuery = true)
    Optional<Ledger> findByStatusListCredentialIdAndStatusListIndex(@Param("statusListCredential") String statusListCredential, @Param("statusListIndex") Long statusListIndex);
}