package org.cybersecurity.repositories.user;

import org.cybersecurity.model.user.BaseUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<BaseUser, Long> {
    Optional<BaseUser> findByEmail(String email);
}
