package com.shoppingmall.login.controller;

import com.shoppingmall.login.security.jwt.JwtTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@RestController
@RequestMapping("/api/oauth")
public class OAuthController {

    private final JwtTokenProvider jwtTokenProvider;
    private final Logger LOGGER = LoggerFactory.getLogger(OAuthController.class);

    @Autowired
    public OAuthController(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @GetMapping("/get/authority")
    public ResponseEntity<List<String>> getAuthorities(@RequestHeader String refreshToken) {
        Authentication authentication = jwtTokenProvider.getAuthentication(refreshToken);
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        ArrayList<String> auths = new ArrayList<>();
        authorities.forEach(grantedAuthority -> {
            LOGGER.debug(grantedAuthority.toString());
            auths.add(grantedAuthority.toString());
        });
        return ResponseEntity.ok(auths);
    }

}