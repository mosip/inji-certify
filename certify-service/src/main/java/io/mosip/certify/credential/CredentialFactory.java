package io.mosip.certify.credential;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import io.mosip.certify.enums.CredentialFormat;
import lombok.extern.slf4j.Slf4j;



/***
 * Credential Factory class
 **/
@Slf4j
@Component
public class CredentialFactory {

    @Autowired
    private List<Credential> credentials;

    // Factory method to create objects based on type
    public Optional<Credential> getCredential(CredentialFormat format) {
        if (format == null) {
            return null;
        }

        return credentials.stream()
            .filter(service -> service.canHandle(format.toString()))
            .findFirst();
    }
}