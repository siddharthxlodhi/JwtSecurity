package com.sid.JwtSecuritty.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ActivationTokenRepository extends JpaRepository<ActivationToken, Integer> {

    Optional<ActivationToken> findByActivationToken(String token);
}
