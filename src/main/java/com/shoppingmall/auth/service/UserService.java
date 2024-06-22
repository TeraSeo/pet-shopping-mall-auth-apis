package com.shoppingmall.auth.service;

import com.shoppingmall.auth.entity.User;
import com.shoppingmall.auth.security.jwt.JwtToken;

import java.util.Optional;

public interface UserService {
    Boolean registerUser(User user);

    Boolean loginUser(String email, String password);

    Boolean checkEmailExistence(String email);

    User setUserUpdatedTime(User user);

    Boolean resetPassword(String email, String password);

    JwtToken checkIsVerified(String email);

    Long getUserId(String email);
}
