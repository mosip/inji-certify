/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.constants;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Enum for IAR (Interactive Authorization Request) status values
 * Provides type safety and validation for status values
 */
public enum IarStatus {
    
    /**
     * Interaction is required (OpenID4VP presentation)
     */
    REQUIRE_INTERACTION("require_interaction"),
    
    /**
     * Authorization is complete, no interaction needed
     */
    OK("ok"),
    
    /**
     * Error occurred during authorization
     */
    ERROR("error");
    
    private final String value;
    
    IarStatus(String value) {
        this.value = value;
    }
    
    /**
     * Get the string value of the status
     * @return the string representation of the status
     */
    @JsonValue
    public String getValue() {
        return value;
    }
    
    /**
     * Get IarStatus from string value
     * @param value the string value to convert
     * @return the corresponding IarStatus enum
     * @throws IllegalArgumentException if the value is not supported
     */
    public static IarStatus fromValue(String value) {
        if (value == null) {
            throw new IllegalArgumentException("Status value cannot be null");
        }
        
        for (IarStatus status : IarStatus.values()) {
            if (status.value.equals(value)) {
                return status;
            }
        }
        
        throw new IllegalArgumentException("Unsupported status value: " + value);
    }
    
    /**
     * Check if a string value is a valid IAR status
     * @param value the string value to check
     * @return true if the value is valid, false otherwise
     */
    public static boolean isValid(String value) {
        if (value == null) {
            return false;
        }
        
        for (IarStatus status : IarStatus.values()) {
            if (status.value.equals(value)) {
                return true;
            }
        }
        
        return false;
    }
    
    @Override
    public String toString() {
        return value;
    }
}
