package com.innowise.authentication.service.dto.mapper;

import com.innowise.authentication.repository.entity.UserCredentials;
import com.innowise.authentication.service.dto.RegistrationResponseDto;
import com.innowise.authentication.service.dto.RegistrationRequestDto;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingConstants;
import org.mapstruct.ReportingPolicy;

@Mapper(unmappedTargetPolicy = ReportingPolicy.IGNORE,
        componentModel = MappingConstants.ComponentModel.SPRING)
public interface CredentialsMapper {

    @Mapping(target = "id", ignore = true)
    UserCredentials requestToEntity(RegistrationRequestDto request);

    RegistrationResponseDto entityToResponse(UserCredentials credentials);
}
