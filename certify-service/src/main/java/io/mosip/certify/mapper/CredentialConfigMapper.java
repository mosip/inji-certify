package io.mosip.certify.mapper;

import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.enums.CredentialStatusPurpose;
import org.mapstruct.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface CredentialConfigMapper {
    @Mapping(target = "configId", ignore = true)
    @Mapping(target = "status", ignore = true)
    @Mapping(target = "createdTimes", expression = "java(java.time.LocalDateTime.now())")
    @Mapping(target = "updatedTimes", ignore = true)
    @Mapping(target = "context", source = "context", qualifiedByName = "listToCommaSeparatedString")
    @Mapping(target = "credentialType", source = "credentialType", qualifiedByName = "listToCommaSeparatedString")
    @Mapping(target = "credentialStatusPurpose", source = "credentialStatusPurpose", qualifiedByName = "mapCredentialStatusPurpose")
    CredentialConfig toEntity(CredentialConfigurationDTO dto);

    // Convert Entity to DTO
    @Mapping(target = "context", source = "context", qualifiedByName = "commaSeparatedStringToList")
    @Mapping(target = "credentialType", source = "credentialType", qualifiedByName = "commaSeparatedStringToList")
    @Mapping(target = "credentialStatusPurpose", source = "credentialStatusPurpose", qualifiedByName = "mapCredentialStatusPurposeToString")
    CredentialConfigurationDTO toDto(CredentialConfig entity);

    // Update existing entity with DTO data
    @Mapping(target = "configId", ignore = true)
    @Mapping(target = "status", ignore = true)
    @Mapping(target = "createdTimes", ignore = true)
    @Mapping(target = "updatedTimes", expression = "java(java.time.LocalDateTime.now())")
    @Mapping(target = "context", source = "context", qualifiedByName = "listToCommaSeparatedString")
    @Mapping(target = "credentialType", source = "credentialType", qualifiedByName = "listToCommaSeparatedString")
    @Mapping(target = "credentialStatusPurpose", source = "credentialStatusPurpose", qualifiedByName = "mapCredentialStatusPurpose")
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

    @Named("mapCredentialStatusPurpose")
    default io.mosip.certify.enums.CredentialStatusPurpose mapCredentialStatusPurpose(String credentialStatusPurpose) {
        return credentialStatusPurpose != null
                ? CredentialStatusPurpose.fromString(credentialStatusPurpose)
                : null;
    }

    @Named("mapCredentialStatusPurposeToString")
    default String mapCredentialStatusPurposeToString(CredentialStatusPurpose credentialStatusPurpose) {
        return credentialStatusPurpose != null ? credentialStatusPurpose.toString() : null;
    }
}
