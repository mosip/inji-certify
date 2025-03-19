package io.mosip.certify.mapper;

import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.entity.CredentialConfig;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;
import org.mapstruct.ReportingPolicy;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface CredentialConfigMapper {
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "status", ignore = true)
    @Mapping(target = "createdTime", expression = "java(java.time.LocalDateTime.now())")
    @Mapping(target = "updatedTime", ignore = true)
    CredentialConfig toEntity(CredentialConfigurationDTO dto);

    // Convert Entity to DTO
    CredentialConfigurationDTO toDto(CredentialConfig entity);

    // Update existing entity with DTO data
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "status", ignore = true)
    @Mapping(target = "createdTime", ignore = true)
    @Mapping(target = "updatedTime", expression = "java(java.time.LocalDateTime.now())")
    void updateEntityFromDto(CredentialConfigurationDTO dto, @MappingTarget CredentialConfig entity);
}
