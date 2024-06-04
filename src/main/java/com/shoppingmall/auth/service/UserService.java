package com.shoppingmall.auth.service;

import com.shoppingmall.auth.entity.User;

public interface UserService {
    Boolean registerUser(User user);

    Boolean loginUser(String email, String password);

    Boolean checkEmailExistence(String email);

    void setUserUpdatedTime(String email);
}
