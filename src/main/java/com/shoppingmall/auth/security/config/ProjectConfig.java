//package com.shoppingmall.auth.security.config;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.MediaType;
//import org.springframework.web.reactive.function.client.WebClient;
//
//@Configuration
//public class ProjectConfig {
//
//    @Bean
//    public WebClient webClient(WebClient.Builder builder) {
//        return builder
//                .baseUrl("http://localhost:8082")
//                .defaultHeaders(
//                        httpHeaders -> {
//                            httpHeaders.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
//                        }
//                ).build();
//    }
//
//}
