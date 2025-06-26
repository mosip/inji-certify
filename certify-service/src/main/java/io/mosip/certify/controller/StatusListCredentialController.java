/*More actions
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.controller;

import io.mosip.certify.core.dto.VCError;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.services.StatusListCredentialService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.util.Locale;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/status-list")
public class StatusListCredentialController {

    @Autowired
    private StatusListCredentialService statusListCredentialService;

    @Autowired
    MessageSource messageSource;

    /**
     * Get Status List Credential by ID with optional fragment support
     * Handles URLs like: /{id} or /{id}#{fragment}
     *
     * @param id The status list credential ID
    //     * @param fragment Optional fragment identifier (for specific index references)
     * @return Status List VC JSON document
     * @throws CertifyException
     */
    @GetMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public String getStatusListById(@PathVariable("id") String id) throws CertifyException {

        log.info("Retrieving status list credential with ID: {}", id);
        return statusListCredentialService.getStatusListCredential(id);
    }

    @ResponseBody
    @ExceptionHandler(CertifyException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public VCError statusListNotFoundExceptionHandler(CertifyException ex) {
        VCError vcError = new VCError();
        vcError.setError(ex.getErrorCode());
        vcError.setError_description(messageSource.getMessage(ex.getErrorCode(), null, ex.getErrorCode(), Locale.getDefault()));
        return vcError;
    }
}