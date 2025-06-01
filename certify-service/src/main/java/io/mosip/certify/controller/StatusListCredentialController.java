package io.mosip.certify.controller;

import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.services.StatusListCredentialService;
import io.mosip.certify.core.exception.CertifyException;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

/**
 * REST Controller for Status List Credential operations
 * Handles retrieval of Status List VCs and credential status checking
 */
@Slf4j
@RestController
@RequestMapping("/status-list")
public class StatusListCredentialController {

    @Autowired
    private StatusListCredentialService statusListCredentialService;

    /**
     * Get Status List Credential by ID with optional fragment support
     * Handles URLs like: /{id} or /{id}#{fragment}
     *
     * @param id The status list credential ID
     * @param fragment Optional fragment identifier (for specific index references)
     * @return ResponseEntity containing the Status List VC JSON document
     */
    @GetMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getStatusListById(
            @PathVariable("id") String id,
            @RequestParam(value = "fragment", required = false) String fragment) {

        log.info("Retrieving status list credential with ID: {} and fragment: {}", id, fragment);

        try {
            // Find the status list credential by ID
            Optional<StatusListCredential> statusListOpt = statusListCredentialService.findStatusListById(id);

            if (statusListOpt.isEmpty()) {
                log.warn("Status list credential not found for ID: {}", id);
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(createErrorResponse("STATUS_RETRIEVAL_ERROR", "Status List not found for the given ID"));
            }

            StatusListCredential statusList = statusListOpt.get();

            // Parse the VC document
            JSONObject vcDocument;
            try {
                vcDocument = new JSONObject(statusList.getVcDocument());
            } catch (Exception e) {
                log.error("Error parsing VC document for status list ID: {}", id, e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(createErrorResponse("STATUS_RETRIEVAL_ERROR", "Internal server error during retrieval"));
            }

            // If fragment is provided, validate that the requested index exists in the status list
            if (fragment != null && !fragment.isEmpty()) {
                try {
                    long requestedIndex = Long.parseLong(fragment);

                    // Validate that the requested index is within the capacity of this status list
                    if (requestedIndex < 0 || requestedIndex >= statusList.getCapacity()) {
                        log.warn("Requested index {} is out of bounds for status list {} with capacity {}",
                                requestedIndex, id, statusList.getCapacity());
                        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                                .body(createErrorResponse("INDEX_OUT_OF_BOUNDS", "Requested index is out of bounds"));
                    }

                    log.info("Fragment validation successful for index: {} in status list: {}", requestedIndex, id);

                } catch (NumberFormatException e) {
                    log.warn("Invalid fragment format: {}", fragment);
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(createErrorResponse("INVALID_FRAGMENT", "Invalid fragment format"));
                }
            }

            // Set appropriate headers for caching
            return ResponseEntity.ok()
                    .header("Cache-Control", "max-age=300") // 5 minutes cache
                    .header("ETag", "\"" + statusList.getId() + "-" + statusList.getCreatedDtimes().toString() + "\"")
                    .header("Last-Modified", statusList.getCreatedDtimes().toString())
                    .body(vcDocument.toString()); // Return as Map for proper JSON serialization

        } catch (CertifyException e) {
            log.error("CertifyException while retrieving status list credential: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("STATUS_RETRIEVAL_ERROR", "Internal server error during retrieval"));
        } catch (Exception e) {
            log.error("Unexpected error retrieving status list credential with ID: {}", id, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("STATUS_RETRIEVAL_ERROR", "Internal server error during retrieval"));
        }
    }

    /**
     * Create standardized error response
     */
    private Object createErrorResponse(String errorCode, String message) {
        return new ErrorResponse(errorCode, message);
    }

    /**
     * Inner class for error responses
     */
    public static class ErrorResponse {
        private String errorCode;
        private String message;
        private long timestamp;

        public ErrorResponse(String errorCode, String message) {
            this.errorCode = errorCode;
            this.message = message;
            this.timestamp = System.currentTimeMillis();
        }

        // Getters
        public String getErrorCode() { return errorCode; }
        public String getMessage() { return message; }
        public long getTimestamp() { return timestamp; }
    }
}