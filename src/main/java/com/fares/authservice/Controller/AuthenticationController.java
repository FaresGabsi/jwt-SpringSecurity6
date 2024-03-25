package com.fares.authservice.Controller;

import com.fares.authservice.Entities.ApplicationUser;
import com.fares.authservice.Entities.LoginResponseDTO;
import com.fares.authservice.Entities.RegistrationDTO;
import com.fares.authservice.Services.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@CrossOrigin("*")

public class AuthenticationController {
    @Autowired
    private  AuthenticationService authenticationService;
    @PostMapping("/register")
    public ApplicationUser registerUser(@RequestBody RegistrationDTO registrationDTO){
        return authenticationService.registerUser(registrationDTO.getUsername(),registrationDTO.getPassword());
    }

    @PostMapping("/login")
    public LoginResponseDTO loginUser(@RequestBody RegistrationDTO registrationDTO){
        return authenticationService.loginUser(registrationDTO.getUsername(),registrationDTO.getPassword());
    }

}
