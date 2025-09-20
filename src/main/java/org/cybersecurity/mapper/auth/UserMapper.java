package org.cybersecurity.mapper.auth;

import org.cybersecurity.dto.auth.RegisterUserDto;
import org.cybersecurity.model.user.BaseUser;

public class UserMapper {
    public static BaseUser toEntity(RegisterUserDto dto) {
        if (dto == null)
            return null;

        BaseUser entity = new BaseUser();
        entity.setPassword(dto.getPassword());
        entity.setEmail(dto.getEmail());
        entity.setFirstName(dto.getFirstName());
        entity.setLastName(dto.getLastName());
        entity.setUserRole(dto.getUserRole());
        entity.setOrganization(dto.getOrganization());
        return entity;
    }
}
