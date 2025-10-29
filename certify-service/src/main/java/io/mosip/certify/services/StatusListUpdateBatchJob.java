package io.mosip.certify.services;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.utils.BitStringStatusListUtils;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.core.LockAssert;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Batch job service for updating Status List Credentials
 * Runs every minute(can be configured) to process new credential status transactions and update status lists
 */
@Slf4j
@Service
public class StatusListUpdateBatchJob {

    @Autowired
    private CredentialStatusTransactionRepository transactionRepository;

    @Autowired
    private StatusListCredentialRepository statusListRepository;

    @Autowired
    private StatusListCredentialService statusListCredentialService;

    @Value("${mosip.certify.batch.status-list-update.enabled:true}")
    private boolean batchJobEnabled;

    @Value("${mosip.certify.batch.status-list-update.batch-size:1000}")
    private int batchSize;

    /**
     * Scheduled method that runs periodically (schedule controlled by cron expression property)
     * to update status lists by processing new credential status transactions.
     */
    @Scheduled(cron = "${mosip.certify.batch.status-list-update.cron-expression:0 0/1 * * * *}")
    @SchedulerLock(
            name = "updateStatusLists",
            lockAtMostFor = "${mosip.certify.batch.status-list-update.lock-at-most-for:50m}",
            lockAtLeastFor = "${mosip.certify.batch.status-list-update.lock-at-least-for:50s}"
    )
    public void updateStatusLists() {
        LockAssert.assertLocked();
        if (!batchJobEnabled) {
            log.info("Status list update batch job is disabled");
            return;
        }

        log.info("Starting status list update batch job");

        try {
            // Fetch a batch of unprocessed transactions
            List<CredentialStatusTransaction> newTransactions = transactionRepository.findByIsProcessedFalseOrderByCreatedDtimesAsc(PageRequest.of(0, batchSize));

            if (newTransactions.isEmpty()) {
                log.info("No unprocessed transactions found");
                return;
            }

            log.info("Found {} unprocessed transactions to process", newTransactions.size());

            // Group transactions by status list credential ID
            Map<String, List<CredentialStatusTransaction>> transactionsByStatusList = groupTransactionsByStatusList(newTransactions);

            // Update each affected status list
            int updatedLists = 0;
            for (Map.Entry<String, List<CredentialStatusTransaction>> entry : transactionsByStatusList.entrySet()) {
                String statusListId = entry.getKey();
                List<CredentialStatusTransaction> transactions = entry.getValue();

                try {
                    updateStatusList(statusListId, transactions);
                    updatedLists++;
                    log.info("Successfully updated status list: {} and marked {} transactions as processed", statusListId, transactions.size());
                } catch (Exception e) {
                    log.error("Failed to update status list: {}", statusListId, e);
                    // Continue processing other status lists even if one fails
                }
            }

            log.info("Status list update batch job completed successfully. Updated {} status lists", updatedLists);

        } catch (Exception e) {
            log.error("Error in status list update batch job", e);
            throw new CertifyException(ErrorConstants.BATCH_JOB_EXECUTION_FAILED);
        }
    }

    /**
     * Group transactions by their status list credential ID
     */
    private Map<String, List<CredentialStatusTransaction>> groupTransactionsByStatusList(List<CredentialStatusTransaction> transactions) {

        return transactions.stream()
                .filter(t -> t.getStatusListCredentialId() != null)
                .collect(Collectors.groupingBy(CredentialStatusTransaction::getStatusListCredentialId));
    }

    /**
     * Update a specific status list with the given transactions
     */
    @Transactional
    public void updateStatusList(String statusListId, List<CredentialStatusTransaction> transactions) {
        log.info("Updating status list {} with {} transactions", statusListId, transactions.size());

        try {
            // Fetch the current status list credential
            Optional<StatusListCredential> optionalStatusList = statusListRepository.findById(statusListId);

            if (optionalStatusList.isEmpty()) {
                log.error("Status list credential not found: {}", statusListId);
                throw new CertifyException(ErrorConstants.STATUS_LIST_NOT_FOUND);
            }

            StatusListCredential statusListCredential = optionalStatusList.get();

            // Apply transaction updates to the status data
            Map<Long, Boolean> updatedStatuses = getUpdatedStatus(transactions);

            JSONObject vcDocument = new JSONObject(statusListCredential.getVcDocument());

            // Generate new encoded list
            String newEncodedList = BitStringStatusListUtils.updateEncodedList(vcDocument.getJSONObject("credentialSubject").getString("encodedList"),updatedStatuses, statusListCredential.getCapacity());

            // Update the status list credential with new encoded list
            updateStatusListCredential(statusListCredential, newEncodedList);

            // Mark transactions as processed
            LocalDateTime processedTime = LocalDateTime.now();
            for (CredentialStatusTransaction txn : transactions) {
                txn.setProcessedTime(processedTime);
                txn.setIsProcessed(true);
            }
            transactionRepository.saveAll(transactions);

            log.info("Successfully updated status list credential: {}", statusListId);

        } catch (Exception e) {
            log.error("Error updating status list: {}", statusListId, e);
            throw new CertifyException(ErrorConstants.STATUS_LIST_UPDATE_FAILED);
        }
    }

    /** Returns a map of status list index to the latest status value, based on transaction creation time.
     * If multiple transactions exist for the same index, the latest one (by createdDtimes) is used.
     */
    private Map<Long, Boolean> getUpdatedStatus(List<CredentialStatusTransaction> transactions) {
        return transactions.stream()
                .filter(t -> t.getStatusListIndex() != null)
                .sorted(Comparator.comparing(CredentialStatusTransaction::getCreatedDtimes))
                .collect(Collectors.toMap(
                        CredentialStatusTransaction::getStatusListIndex,
                        CredentialStatusTransaction::getStatusValue,
                        (first, second) -> second,
                        HashMap::new
                ));
    }


    /**
     * Update the status list credential with the new encoded list
     */
    @Transactional
    public void updateStatusListCredential(StatusListCredential statusListCredential, String newEncodedList) {
        try {
            log.info("Starting update of StatusListCredential with ID: {}", statusListCredential.getId());

            // Parse the current VC document
            JSONObject vcDocument = new JSONObject(statusListCredential.getVcDocument());
            log.info("Parsed VC document for StatusListCredential ID: {}", statusListCredential.getId());

            // Update the encodedList in the credential subject
            JSONObject credentialSubject = vcDocument.getJSONObject("credentialSubject");
            credentialSubject.put("encodedList", newEncodedList);
            log.info("Updated encodedList for StatusListCredential ID: {}", statusListCredential.getId());

            // Update timestamps
            String newValidFrom = new Date().toInstant().toString();
            vcDocument.put("validFrom", newValidFrom);
            log.info("Set new validFrom timestamp: {} for StatusListCredential ID: {}", newValidFrom, statusListCredential.getId());

            // Re-sign the status list credential
            String updatedVcDocument = statusListCredentialService.resignStatusListCredential(vcDocument.toString());
            log.info("Re-signed VC document for StatusListCredential ID: {}", statusListCredential.getId());

            // Update the database record
            statusListCredential.setVcDocument(updatedVcDocument);
            statusListCredential.setUpdatedDtimes(LocalDateTime.now());
            statusListRepository.save(statusListCredential);

            log.info("Successfully updated and saved StatusListCredential ID: {}", statusListCredential.getId());

        } catch (Exception e) {
            log.error("Error updating StatusListCredential ID: {}", statusListCredential.getId(), e);
            throw new CertifyException(ErrorConstants.STATUS_LIST_CREDENTIAL_UPDATE_FAILED);
        }
    }
}