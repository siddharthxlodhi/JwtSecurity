package com.sid.JwtSecuritty;

import com.sid.JwtSecuritty.role.RoleRepository;
import com.sid.JwtSecuritty.role.Roles;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

import java.time.LocalDateTime;

@EnableAsync
@SpringBootApplication
public class JwtSecurittyApplication implements CommandLineRunner {

    @Autowired
    private RoleRepository roleRepository;

    public static void main(String[] args) {
        SpringApplication.run(JwtSecurittyApplication.class, args);
    }

    @Override
    public void run(String... args) {
//        Roles roles = new Roles();
//        roles.setName("USER");
//        roles.setCreatedDate(LocalDateTime.now());
//        roleRepository.save(roles);
    }
}
