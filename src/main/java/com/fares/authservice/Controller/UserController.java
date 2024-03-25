package com.fares.authservice.Controller;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
@CrossOrigin("*") // Allow all origins to access this API
public class UserController {
    @GetMapping("/")
    public String helloUserController() {
        return "Hello, User!";
    }
}
