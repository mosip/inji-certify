package io.mosip.certify.credential;

import java.util.Optional;
import java.util.List;

import io.mosip.certify.core.constants.VCFormats;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;


/***
 * Credential Factory class
 **/
@Slf4j
@Service
public class CredentialFactory {

    private final List<Credential> credentials;

    public CredentialFactory(List<Credential> credentials) {
        this.credentials = credentials;
    }

    /**
     * Factory method to create objects based on the given format.
     * 
     * Known formats are defined in 
     * @see VCFormats
     * @param format
     * @return
     */
    public Optional<Credential> getCredential(String format) {
        if (format == null) {
            return Optional.empty();
        }
        return credentials.stream()
                .filter(credential -> credential.canHandle(format))
                .findFirst();
        
    }
}