package io.mosip.certify.utils;

import io.mosip.certify.core.dto.ClaimsDisplayFieldsConfigDTO;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.attributes.Claims;
import org.mapstruct.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface CredentialConfigMapper {
    @Mapping(target = "configId", ignore = true)
    @Mapping(target = "status", ignore = true)
    @Mapping(target = "createdTimes", expression = "java(java.time.LocalDateTime.now())")
    @Mapping(target = "updatedTimes", ignore = true)
    @Mapping(target = "context", source = "contextURLs", qualifiedByName = "listToCommaSeparatedString")
    @Mapping(target = "credentialType", source = "credentialTypes", qualifiedByName = "listToCommaSeparatedString")
    @Mapping(target = "display", source = "metaDataDisplay")
    @Mapping(target = "order", source = "displayOrder")
    @Mapping(target = "cryptographicBindingMethodsSupported", ignore = true)
    @Mapping(target = "credentialSigningAlgValuesSupported", ignore = true)
    @Mapping(target = "proofTypesSupported", ignore = true)
    @Mapping(target = "msoMdocClaims", source = "msoMdocClaims", qualifiedByName = "mapClaimsToEntity")
    @Mapping(target = "claims", source = "claims")
    CredentialConfig toEntity(CredentialConfigurationDTO dto);

    // Convert Entity to DTO
    @Mapping(target = "contextURLs", source = "context", qualifiedByName = "commaSeparatedStringToList")
    @Mapping(target = "credentialTypes", source = "credentialType", qualifiedByName = "commaSeparatedStringToList")
    @Mapping(target = "metaDataDisplay", source = "display")
    @Mapping(target = "displayOrder", source = "order")
    @Mapping(target = "msoMdocClaims", source = "msoMdocClaims", qualifiedByName = "mapClaimsToDto")
    @Mapping(target = "claims", source = "claims")
    CredentialConfigurationDTO toDto(CredentialConfig entity);

    @Mapping(target = "configId", ignore = true)
    @Mapping(target = "status", ignore = true)
    @Mapping(target = "createdTimes", ignore = true)
    @Mapping(target = "updatedTimes", expression = "java(java.time.LocalDateTime.now())")
    @Mapping(target = "context", source = "contextURLs", qualifiedByName = "listToCommaSeparatedString")
    @Mapping(target = "credentialType", source = "credentialTypes", qualifiedByName = "listToCommaSeparatedString")
    @Mapping(target = "display", source = "metaDataDisplay")
    @Mapping(target = "order", source = "displayOrder")
    @Mapping(target = "cryptographicBindingMethodsSupported", ignore = true)
    @Mapping(target = "credentialSigningAlgValuesSupported", ignore = true)
    @Mapping(target = "proofTypesSupported", ignore = true)
    @Mapping(target = "msoMdocClaims", source = "msoMdocClaims", qualifiedByName = "mapClaimsToEntity")
    @Mapping(target = "claims", source = "claims")
    void updateEntityFromDto(CredentialConfigurationDTO dto, @MappingTarget CredentialConfig entity);

    Claims toEntity(ClaimsDisplayFieldsConfigDTO dto);
    ClaimsDisplayFieldsConfigDTO toDto(Claims dto);

    @Named("listToCommaSeparatedString")
    default String listToCommaSeparatedString(List<String> list) {
        if (list == null || list.isEmpty()) {
            return null;
        }
        return list.stream()
                .sorted()
                .collect(Collectors.joining(","));
    }

    @Named("commaSeparatedStringToList")
    default List<String> commaSeparatedStringToList(String str) {
        if (str == null || str.isEmpty()) {
            return new ArrayList<>();
        }
        return Arrays.stream(str.split(","))
                .map(String::trim)
                .collect(Collectors.toList());
    }

    @Named("mapClaimsToEntity")
    default Map<String, Map<String, Claims>> mapClaims(
            Map<String, Map<String, ClaimsDisplayFieldsConfigDTO>> source) {
        if (source == null) return null;
        Map<String, Map<String, Claims>> result = new java.util.HashMap<>();
        for (Map.Entry<String, Map<String, ClaimsDisplayFieldsConfigDTO>> entry : source.entrySet()) {
            Map<String, Claims> innerMap = new java.util.HashMap<>();
            for (Map.Entry<String, ClaimsDisplayFieldsConfigDTO> innerEntry : entry.getValue().entrySet()) {
                innerMap.put(innerEntry.getKey(), toEntity(innerEntry.getValue()));
            }
            result.put(entry.getKey(), innerMap);
        }
        return result;
    }

    @Named("mapClaimsToDto")
    default Map<String, Map<String, ClaimsDisplayFieldsConfigDTO>> mapClaimsToDto(
            Map<String, Map<String, Claims>> source) {
        if (source == null) return null;
        Map<String, Map<String, ClaimsDisplayFieldsConfigDTO>> result = new java.util.HashMap<>();
        for (Map.Entry<String, Map<String, Claims>> entry : source.entrySet()) {
            Map<String, ClaimsDisplayFieldsConfigDTO> innerMap = new java.util.HashMap<>();
            for (Map.Entry<String, Claims> innerEntry : entry.getValue().entrySet()) {
                innerMap.put(innerEntry.getKey(), toDto(innerEntry.getValue()));
            }
            result.put(entry.getKey(), innerMap);
        }
        return result;
    }

}