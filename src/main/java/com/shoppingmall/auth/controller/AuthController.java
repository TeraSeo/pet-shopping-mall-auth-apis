package com.shoppingmall.auth.controller;

import com.shoppingmall.auth.entity.Role;
import com.shoppingmall.auth.entity.User;
import com.shoppingmall.auth.security.jwt.JwtToken;
import com.shoppingmall.auth.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
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

    @GetMapping("/email/valid")
    public ResponseEntity<Boolean> checkEmailExistence(@RequestHeader String email) {
        LOGGER.debug("check is email valid");
        Boolean isEmailValid = userService.checkEmailExistence(email);
        return ResponseEntity.ok(isEmailValid);
    }

    @PutMapping("/reset/password")
    public ResponseEntity<Boolean> resetPassword(@RequestBody User user) {
        String email = user.getEmail();
        String password = user.getPassword();
        LOGGER.debug("reset password");
        Boolean isChanged = userService.resetPassword(email, password);
        return ResponseEntity.ok(isChanged);
    }

    @GetMapping("/check/isVerified")
    public ResponseEntity<Boolean> checkIsVerified(@RequestParam String email) {
        LOGGER.debug("check is Verified");
        LOGGER.debug("email: " + email);
        JwtToken jwtToken = userService.checkIsVerified(email);
        if (jwtToken != null) {
            String accessToken = jwtToken.getAccessToken();
            String refreshToken = jwtToken.getRefreshToken();

            HttpHeaders headers = new HttpHeaders();
            headers.set("accessToken", accessToken);
            headers.set("refreshToken", refreshToken);

            return new ResponseEntity<>(true, headers, HttpStatus.OK);
        }
        return new ResponseEntity<>(false, HttpStatus.OK);
    }
}