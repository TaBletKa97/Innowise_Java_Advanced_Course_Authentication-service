package com.innowise.authentication.service.dto.mapper;

import com.innowise.authentication.repository.entity.UserCredentials;
import com.innowise.authentication.service.dto.RegistrationResponseDto;
import com.innowise.authentication.service.dto.RegistrationRequestDto;
import com.innowise.authentication.service.dto.UserRegistrationRequestDto;
import org.mapstruct.*;

@Mapper(unmappedTargetPolicy = ReportingPolicy.IGNORE,
        componentModel = MappingConstants.ComponentModel.SPRING)
public interface CredentialsMapper {

    @Mapping(target = "id", ignore = true)
    UserCredentials requestToEntity(RegistrationRequestDto request);

    RegistrationResponseDto entityToResponse(UserCredentials credentials);

    @Mapping(target = "active", constant = "true")
    @Mapping(target = "id", expression = "java(id)")
    UserRegistrationRequestDto prepareRequestPassword(@Context Long id, RegistrationRequestDto requestDto);
}
