package com.example.demo.controller;

import com.example.demo.payload.LoginRequest;
import com.example.demo.payload.LoginResponse;
import com.example.demo.service.UserService;
import com.example.demo.util.JwtUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "Authentication management APIs")

public class AuthController {

    private final JwtUtil jwtUtil;
    private final UserService userService;

    public AuthController(JwtUtil jwtUtil, UserService userService) {
        this.jwtUtil = jwtUtil;
        this.userService = userService;
    }
    @Operation(summary = "Login user",
            description = "Authenticates user and returns JWT token")

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        boolean valid = userService.checkLogin(request.getUsername(), request.getPassword());
        if (valid) {
            String token = jwtUtil.generateToken(request.getUsername());
            return ResponseEntity.ok(new LoginResponse(token));
        }
        return ResponseEntity.status(401).body("Invalid username or password");
    }
    @Operation(summary = "Register new user",
            description = "Creates a new user account")

    // API đăng ký user mới (optional)
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody LoginRequest request) {
        userService.registerUser(request.getUsername(), request.getPassword());
        return ResponseEntity.ok("User registered successfully");
    }
}
