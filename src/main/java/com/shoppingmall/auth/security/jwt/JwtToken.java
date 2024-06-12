package com.shoppingmall.auth.security.jwt;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class JwtToken {

    String grantType;
    String accessToken;
    String refreshToken;

}
