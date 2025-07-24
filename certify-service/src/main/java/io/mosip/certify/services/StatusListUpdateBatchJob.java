package io.mosip.certify.services;

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
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Batch job service for updating Status List Credentials
 * Runs hourly to process new credential status transactions and update status lists
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

    @Value("${mosip.certify.batch.status-list-update.since-time:1970-01-01T00:00:00}")
    private String sinceTime;

    // Track last processed timestamp to avoid reprocessing
    private LocalDateTime lastProcessedTime = null;

    /**
     * Scheduled method that runs every hour to update status lists
     * Uses @Scheduled with fixedRate to run every hour (3600000 ms)
     */
    @Scheduled(cron = "${mosip.certify.batch.status-list-update.cron-expression:0 0 * * * *}")
    @SchedulerLock(
            name = "updateStatusLists",
            lockAtMostFor = "${mosip.certify.batch.status-list-update.lock-at-most-for:50m}",
            lockAtLeastFor = "${mosip.certify.batch.status-list-update.lock-at-least-for:5m}"
    )
    @Transactional
    public void updateStatusLists() {
        LockAssert.assertLocked();
        if (!batchJobEnabled) {
            log.info("Status list update batch job is disabled");
            return;
        }

        log.info("Starting status list update batch job");

        try {
            // Determine the starting timestamp for processing
            LocalDateTime startTime = determineStartTime();
            log.info("Processing transactions since: {}", startTime);

            // Fetch new transactions
            List<CredentialStatusTransaction> newTransactions = fetchNewTransactions(startTime);

            if (newTransactions.isEmpty()) {
                log.info("No new transactions found since {}", startTime);
                return;
            }

            log.info("Found {} new transactions to process", newTransactions.size());

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
                    log.info("Successfully updated status list: {}", statusListId);
                } catch (Exception e) {
                    log.error("Failed to update status list: {}", statusListId, e);
                    // Continue processing other status lists even if one fails
                }
            }

            // Update last processed time
            lastProcessedTime = newTransactions.stream()
                    .map(CredentialStatusTransaction::getCreatedDtimes)
                    .max(LocalDateTime::compareTo)
                    .orElse(LocalDateTime.now());

            log.info("Status list update batch job completed successfully. Updated {} status lists", updatedLists);

        } catch (Exception e) {
            log.error("Error in status list update batch job", e);
            throw new CertifyException("BATCH_JOB_EXECUTION_FAILED");
        }
    }

    /**
     * Determine the starting timestamp for processing transactions
     */
    private LocalDateTime determineStartTime() {
        if (lastProcessedTime != null) {
            return lastProcessedTime;
        }

        // First run - get the latest update time from existing status lists
        Optional<LocalDateTime> lastKnownUpdate = statusListRepository.findMaxUpdatedTime();

        if (lastKnownUpdate.isPresent()) {
            log.info("Using last known status list update time: {}", lastKnownUpdate.get());
            return lastKnownUpdate.get();
        }

        // No previous updates found, using configured since time
        try {
            LocalDateTime defaultStart = LocalDateTime.parse(sinceTime);
            log.info("No previous update time found, using configured default start time: {}", defaultStart);
            return defaultStart;
        } catch (DateTimeParseException e) {
            // Fallback: safe default to 24 hours ago if parsing fails
            LocalDateTime fallbackStart = LocalDateTime.now().minusHours(24);
            log.warn("Failed to parse configured since-time '{}'. Falling back to 24 hours ago: {}", sinceTime, fallbackStart);
            return fallbackStart;
        }
    }

    /**
     * Fetch new transactions since the given timestamp
     */
    private List<CredentialStatusTransaction> fetchNewTransactions(LocalDateTime since) {
        try {
            return transactionRepository.findTransactionsSince(since, batchSize);
        } catch (Exception e) {
            log.error("Error fetching new transactions since {}", since, e);
            throw new CertifyException("TRANSACTION_FETCH_FAILED");
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
                throw new CertifyException("STATUS_LIST_NOT_FOUND");
            }

            StatusListCredential statusListCredential = optionalStatusList.get();

            // Get current status data for this status list
            Map<Long, Boolean> currentStatuses = getCurrentStatusData(statusListId);

            // Apply transaction updates to the status data
            Map<Long, Boolean> updatedStatuses = applyTransactionUpdates(currentStatuses, transactions);

            // Generate new encoded list
            String newEncodedList = BitStringStatusListUtils.generateEncodedList(updatedStatuses, statusListCredential.getCapacity());

            // Update the status list credential with new encoded list
            updateStatusListCredential(statusListCredential, newEncodedList);

            log.info("Successfully updated status list credential: {}", statusListId);

        } catch (Exception e) {
            log.error("Error updating status list: {}", statusListId, e);
            throw new CertifyException("STATUS_LIST_UPDATE_FAILED");
        }
    }

    /**
     * Get current status data for a specific status list from transactions
     */
    private Map<Long, Boolean> getCurrentStatusData(String statusListId) {
        // Get the latest status for each index in this status list
        List<CredentialStatusTransaction> latestTransactions =
                transactionRepository.findLatestStatusByStatusListId(statusListId);

        Map<Long, Boolean> statusMap = new HashMap<>();
        for (CredentialStatusTransaction transaction : latestTransactions) {
            if (transaction.getStatusListIndex() != null) {
                statusMap.put(transaction.getStatusListIndex(), transaction.getStatusValue());
            }
        }

        return statusMap;
    }

    /**
     * Apply transaction updates to the current status data
     */
    private Map<Long, Boolean> applyTransactionUpdates(
            Map<Long, Boolean> currentStatuses,
            List<CredentialStatusTransaction> transactions) {

        Map<Long, Boolean> updatedStatuses = new HashMap<>(currentStatuses);

        // Sort transactions by timestamp to apply them in chronological order
        transactions.sort(Comparator.comparing(CredentialStatusTransaction::getCreatedDtimes));

        for (CredentialStatusTransaction transaction : transactions) {
            if (transaction.getStatusListIndex() != null) {
                updatedStatuses.put(transaction.getStatusListIndex(), transaction.getStatusValue());
            }
        }

        return updatedStatuses;
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
            log.info("Updated encodedList for StatusListCredential ID: {}", newEncodedList);

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
            throw new CertifyException("STATUS_LIST_CREDENTIAL_UPDATE_FAILED");
        }
    }
}