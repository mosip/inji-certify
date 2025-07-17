package io.mosip.certify.mapper;

import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.entity.CredentialConfig;
import org.mapstruct.*;

import java.util.*;
import java.util.stream.Collectors;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface CredentialConfigMapper {
    @Mapping(target = "configId", ignore = true)
    @Mapping(target = "status", ignore = true)
    @Mapping(target = "createdTimes", expression = "java(java.time.LocalDateTime.now())")
    @Mapping(target = "updatedTimes", ignore = true)
    @Mapping(target = "context", source = "contextURLs", qualifiedByName = "listToCommaSeparatedString")
    @Mapping(target = "credentialType", source = "credentialTypes", qualifiedByName = "listToCommaSeparatedString")
    @Mapping(target = "credentialStatusPurpose", ignore = true)
    @Mapping(target = "display", source = "credentialDisplayConfigs")
    @Mapping(target = "order", source = "credentialFieldsDisplayOrder")
    @Mapping(target = "cryptographicBindingMethodsSupported", ignore = true)
    @Mapping(target = "credentialSigningAlgValuesSupported", ignore = true)
    @Mapping(target = "proofTypesSupported", ignore = true)
    CredentialConfig toEntity(CredentialConfigurationDTO dto);

    // Convert Entity to DTO
    @Mapping(target = "contextURLs", source = "context", qualifiedByName = "commaSeparatedStringToList")
    @Mapping(target = "credentialTypes", source = "credentialType", qualifiedByName = "commaSeparatedStringToList")
    @Mapping(target = "credentialDisplayConfigs", source = "display")
    @Mapping(target = "credentialFieldsDisplayOrder", source = "order")
    CredentialConfigurationDTO toDto(CredentialConfig entity);

    // Update existing entity with DTO data
    @Mapping(target = "configId", ignore = true)
    @Mapping(target = "status", ignore = true)
    @Mapping(target = "createdTimes", ignore = true)
    @Mapping(target = "updatedTimes", expression = "java(java.time.LocalDateTime.now())")
    @Mapping(target = "context", source = "contextURLs", qualifiedByName = "listToCommaSeparatedString")
    @Mapping(target = "credentialType", source = "credentialTypes", qualifiedByName = "listToCommaSeparatedString")
    @Mapping(target = "credentialStatusPurpose", ignore = true)
    @Mapping(target = "display", source = "credentialDisplayConfigs")
    @Mapping(target = "order", source = "credentialFieldsDisplayOrder")
    @Mapping(target = "cryptographicBindingMethodsSupported", ignore = true)
    @Mapping(target = "credentialSigningAlgValuesSupported", ignore = true)
    @Mapping(target = "proofTypesSupported", ignore = true)
    void updateEntityFromDto(CredentialConfigurationDTO dto, @MappingTarget CredentialConfig entity);

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
}
