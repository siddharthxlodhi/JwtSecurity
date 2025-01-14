package com.sid.JwtSecuritty.user;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.sid.JwtSecuritty.role.Roles;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.Principal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

import static jakarta.persistence.CascadeType.ALL;
import static jakarta.persistence.FetchType.EAGER;

@Builder
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Table(name = "user_table")
public class User implements UserDetails, Principal {
    @Id
    @GeneratedValue
    private Integer id;
    private String firstName;
    private String lastName;
    @JsonFormat(pattern = "yyyy-MM-dd")
    private LocalDate dateOfBirth;
    private String email;
    private String password;
    private boolean accountLocked;
    private boolean enabled;

    @ManyToMany(cascade = ALL, fetch = EAGER)
    private Set<Roles> roles;
    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdDate;

    @LastModifiedDate
    @Column(insertable = false)
    private LocalDateTime lastModifiedDate;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.roles.stream()
                .map(roles1 -> new SimpleGrantedAuthority(roles1.getName()))
                .collect(Collectors.toSet());
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public String getUsername() {
        return this.email;
    }

    @Override
    public String getName() {
        return email;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !accountLocked;
    }

    public String getFullName() {
        return firstName + " " + lastName;
    }

}
