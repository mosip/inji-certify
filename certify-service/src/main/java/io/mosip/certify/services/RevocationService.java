package io.mosip.certify.services;

//import io.mosip.certify.core.dto.CredentialIssuanceRequest;
//import io.mosip.certify.core.dto.CredentialIssuanceResponse;
import io.mosip.certify.core.dto.CredentialFetchRequest;
import io.mosip.certify.core.dto.CredentialFetchResponse;
import io.mosip.certify.core.dto.CredentialRevocationRequest;
import io.mosip.certify.core.dto.CredentialRevocationResponse;
import io.mosip.certify.exception.CredentialIssuanceException;
import io.mosip.certify.exception.CredentialNotFoundException;
import io.mosip.certify.exception.RevocationException;

/**
 * Service interface for credential revocation operations
 */
public interface RevocationService {

    /**
     * Issue a credential with status tracking capabilities
     * @param request The credential issuance request
     * @return The issued credential response
     * @throws CredentialIssuanceException if credential issuance fails
     */
//    CredentialIssuanceResponse issueCredential(CredentialIssuanceRequest request) throws CredentialIssuanceException;

    /**
     * Fetch credential status information based on filters
     * @param request The credential fetch request containing filters
     * @return The credential status information
     * @throws CredentialNotFoundException if the credential cannot be found
     */
    CredentialFetchResponse fetchCredential(CredentialFetchRequest request) throws CredentialNotFoundException;

    /**
     * Revoke a credential
     * @param request The revocation request with credential ID and reason
     * @return Success message if revocation is successful
     * @throws RevocationException if revocation fails
     */
    CredentialRevocationResponse revokeCredential(CredentialRevocationRequest request) throws RevocationException, CredentialNotFoundException ;
}