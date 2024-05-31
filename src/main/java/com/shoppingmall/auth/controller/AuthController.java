package com.shoppingmall.auth.controller;

import com.shoppingmall.auth.entity.Role;
import com.shoppingmall.auth.entity.User;
import com.shoppingmall.auth.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/login")
    public ResponseEntity<Boolean> login(@RequestHeader String email, @RequestHeader String password) {
        LOGGER.debug("login");
        Boolean isLogin = userService.loginUser(email, password);
        return ResponseEntity.ok(isLogin);
    }

    @PostMapping("/register")
    public ResponseEntity<Boolean> register(@RequestBody User user) {
        user.setRole(Role.USER);
        Boolean isUserExisting = userService.registerUser(user);
        return ResponseEntity.ok(isUserExisting);
    }
}