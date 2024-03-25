package com.fares.authservice;

import com.fares.authservice.Entities.ApplicationUser;
import com.fares.authservice.Entities.Role;
import com.fares.authservice.Repository.RoleRepository;
import com.fares.authservice.Repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Set;

@SpringBootApplication
public class JwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtApplication.class, args);
	}
	@Bean
	CommandLineRunner run(RoleRepository roleRepository, UserRepository userRepository, PasswordEncoder passwordEncoder){
		return args -> {
			if (roleRepository.findByAuthority("ADMIN").isPresent())
				return;
			Role adminRole = roleRepository.save(Role.builder().authority("ADMIN").build());
			Role userRole = roleRepository.save(Role.builder().authority("USER").build());
			Set<Role> roles=new HashSet<>();
			roles.add(adminRole);
			ApplicationUser admin = ApplicationUser.builder()
					.username("admin")
					.password(passwordEncoder.encode("password"))
					.authorities(roles)
					.build();
			userRepository.save(admin);
		};
	}
}
