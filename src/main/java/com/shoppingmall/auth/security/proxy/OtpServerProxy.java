//package com.shoppingmall.auth.security.proxy;
//
//import com.shoppingmall.auth.entity.Otp;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.stereotype.Component;
//import org.springframework.web.reactive.function.BodyInserters;
//import org.springframework.web.reactive.function.client.WebClient;
//
//
//@Component
//public class OtpServerProxy {
//
//    private final WebClient webClient;
//    private final Logger LOGGER = LoggerFactory.getLogger(OtpServerProxy.class);
//
//    @Autowired
//    public OtpServerProxy(WebClient webClient) {
//        this.webClient = webClient;
//    }
//
//    public void sendOtpRequest(String email) {
//        String url = "/api/otp/send";
//        LOGGER.debug("send otp reqeust");
//
//        Otp otp = Otp.builder().email(email).build();
//
//        webClient.post()
//                .uri(url)
//                .body(BodyInserters.fromValue(otp))
//                .retrieve()
//                .bodyToMono(Void.class)
//                .block();
//    }
//
//    public boolean checkOtp(String email, String code) {
//        String url = "/api/otp/checkOtp";
//        LOGGER.debug("check otp");
//
//        Otp otp = Otp.builder().email(email).code(code).build();
//
//        Boolean isCorrect = webClient.get()
//            .uri(uriBuilder -> uriBuilder
//                    .path(url)
//                    .queryParam("email", email)
//                    .queryParam("code", code)
//                    .build())
//            .retrieve()
//            .bodyToMono(Boolean.class)
//            .block();
//
//        return isCorrect;
//    }
//
//}
