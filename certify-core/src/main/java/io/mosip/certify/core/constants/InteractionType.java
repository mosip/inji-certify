/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.constants;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Enum for IAR (Interactive Authorization Request) interaction types
 * Provides type safety and validation for interaction type values
 */
public enum InteractionType {
    
    /**
     * OpenID4VP presentation interaction type
     */
    OPENID4VP_PRESENTATION("openid4vp_presentation"),
    
    /**
     * Redirect to web interaction type (not supported)
     */
    REDIRECT_TO_WEB("redirect_to_web");
    
    private final String value;
    
    InteractionType(String value) {
        this.value = value;
    }
    
    /**
     * Get the string value of the interaction type
     * @return the string representation of the interaction type
     */
    @JsonValue
    public String getValue() {
        return value;
    }
    
    /**
     * Get InteractionType from string value
     * @param value the string value to convert
     * @return the corresponding InteractionType enum
     * @throws IllegalArgumentException if the value is not supported
     */
    public static InteractionType fromValue(String value) {
        if (value == null) {
            throw new IllegalArgumentException("Interaction type value cannot be null");
        }
        
        for (InteractionType type : InteractionType.values()) {
            if (type.value.equals(value)) {
                return type;
            }
        }
        
        throw new IllegalArgumentException("Unsupported interaction type value: " + value);
    }
    
    /**
     * Check if a string value is a valid interaction type
     * @param value the string value to check
     * @return true if the value is valid, false otherwise
     */
    public static boolean isValid(String value) {
        if (value == null) {
            return false;
        }
        
        for (InteractionType type : InteractionType.values()) {
            if (type.value.equals(value)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check if the interaction type is supported
     * @return true if the interaction type is supported, false otherwise
     */
    public boolean isSupported() {
        return this == OPENID4VP_PRESENTATION;
    }
    
    @Override
    public String toString() {
        return value;
    }
}
