package com.sid.JwtSecuritty.JwtConfig;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Integer> {

    @Query("""
            SELECT t from Token t INNER join User  u on t.user.id=u.id
            where u.id= :userId and (t.isRevoked=false and t.expired=false )
            """
    )
    List<Token> findAllValidTokenByUser(Integer userId);

    Optional<Token> findByToken(String token);

}
