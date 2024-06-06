package com.shoppingmall.auth.service;

import com.shoppingmall.auth.entity.User;
import com.shoppingmall.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final Logger LOGGER = LoggerFactory.getLogger(UserServiceImpl.class);

    @Autowired
    public UserServiceImpl(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    public Boolean registerUser(User user) {
        if (user.getEmail() != null) {
            Optional<User> u = userRepository.findByEmail(user.getEmail());
            if (u.isPresent()) {
                LOGGER.debug("existing user");
                return false;
            }
            String encodedPassword = bCryptPasswordEncoder.encode(user.getPassword());
            user.setPassword(encodedPassword);
            userRepository.save(user);
            LOGGER.debug("user registered");
        }
        return true;
    }

    @Override
    public Boolean loginUser(String email, String password) {
        if (password != null) {
            Optional<User> u = userRepository.findByEmail(email);
            if (u.isPresent()) {
                User user = u.get();
                if (bCryptPasswordEncoder.matches(password, user.getPassword())) {
//                    User updatedUser = setUserUpdatedTime(user);
//                    userRepository.save(updatedUser);
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public Boolean checkEmailExistence(String email) {
        Optional<User> u = userRepository.findByEmail(email);
        if (u.isPresent()) {
            User user = u.get();
            if (user.getPassword() != null && user.getPassword() != "") {
                return true;
            }
        }
        return false;
    }

    @Override
    public User setUserUpdatedTime(User user) {
        user.setUpdatedAt(LocalDateTime.now());
        return user;
    }

    @Override
    public Boolean resetPassword(String email, String password) {
        Optional<User> u = userRepository.findByEmail(email);
        if (u.isPresent()) {
            User user =  u.get();
            String encodedPassword = bCryptPasswordEncoder.encode(password);
            user.setPassword(encodedPassword);
            User updatedUser = setUserUpdatedTime(user);
            userRepository.save(updatedUser);
            return true;
        }
        return false;
    }
}
