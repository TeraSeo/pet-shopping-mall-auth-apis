package com.shoppingmall.auth.security.proxy;

import io.jsonwebtoken.lang.Assert;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class OtpServerProxyTest {

    @Autowired
    private OtpServerProxy otpServerProxy;

    @Test
    public void sendOtpRequest() {
        otpServerProxy.sendOtpRequest("seotj0413@gmail.com");
    }

    @Test
    void checkOtp() {
        boolean isCorrect = otpServerProxy.checkOtp("a@gmail.com", "5011");
        Assert.isTrue(isCorrect);
    }
}