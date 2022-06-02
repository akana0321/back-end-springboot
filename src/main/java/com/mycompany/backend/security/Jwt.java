package com.mycompany.backend.security;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.log4j.Log4j2;

@Log4j2
public class Jwt {
  // 상수
  private static final String JWT_SECRET_KEY = "kosa12345";         // 비밀키
  private static final long ACCESS_TOKEN_DURATION = 1000*60*30;     // 30분
  public static final long REFRESH_TOKEN_DURATION = 1000*60*60*24; // 24시간
  
  // Access Token 생성
  public static String createAccessToken(String mid, String authority) {
    log.info("실행");
    String accessToken = null;
    
    try {
      accessToken = Jwts.builder()
                        // 헤더 설정
                        .setHeaderParam("alg", "HS-256")
                        .setHeaderParam("typ", "JWT")
                        // 페이로드 설정
                        .setExpiration(new Date(new Date()
                        .getTime() + ACCESS_TOKEN_DURATION))  // 만료기간
                        .claim("mid", mid)
                        .claim("authority", authority)
                        // 서명 설정
                        .signWith(SignatureAlgorithm.HS256, JWT_SECRET_KEY.getBytes("UTF-8"))
                        .compact();
    } catch(Exception e) {
      log.error(e.getMessage());
    }
    
    return accessToken;
  }
  
 // Refresh Token 생성
 public static String createRefreshToken(String mid, String authority) {
   log.info("실행");
   String refreshToken = null;
   
   try {
     refreshToken = Jwts.builder()
                       // 헤더 설정
                       .setHeaderParam("alg", "HS-256")
                       .setHeaderParam("typ", "JWT")
                       // 페이로드 설정
                       .setExpiration(new Date(new Date().getTime() + REFRESH_TOKEN_DURATION))  // 만료기간
                       .claim("mid", mid)
                       .claim("authority", authority)
                       // 서명 설정
                       .signWith(SignatureAlgorithm.HS256, JWT_SECRET_KEY.getBytes("UTF-8"))
                       .compact();
   } catch(Exception e) {
     log.error(e.getMessage());
   }
   
   return refreshToken;
 }
 
 // 토큰 유효성 판단
 public static boolean validateToken(String token) {
   log.info("실행");
   boolean result = false;
   try {
     result = Jwts.parser()
                  .setSigningKey(JWT_SECRET_KEY.getBytes("UTF-8"))
                  .parseClaimsJws(token)
                  .getBody()
                  .getExpiration()
                  .after(new Date());
   } catch(Exception e) {
     log.error(e.getMessage());
   }
   return result;
 }
 
 // 토큰 만료 시간 얻기
 public static Date getExpiration(String token) {
   log.info("실행");
   Date result = null;
   try {
     result = Jwts.parser()
                  .setSigningKey(JWT_SECRET_KEY.getBytes("UTF-8"))
                  .parseClaimsJws(token)
                  .getBody()
                  .getExpiration();
   } catch(Exception e) {
     log.error(e.getMessage());
   }
   return result;
 }
 
 // 인증 사용자 정보 얻기
 public static Map<String, String> getUserInfo(String token) {
   log.info("실행");
   Map<String, String> result = new HashMap<>();
   try {
     Claims claims = Jwts.parser()
                         .setSigningKey(JWT_SECRET_KEY.getBytes("UTF-8"))
                         .parseClaimsJws(token)
                         .getBody();
     result.put("mid", claims.get("mid", String.class));
     result.put("authority", claims.get("authority", String.class));
   } catch(Exception e) {
     log.error(e.getMessage());
   }
   return result;
 }
 
 // 요청 Authorization 헤더값에서 AccessToken 얻기
 // Bearer "AccessToken 내용"
 public static String getAccessToken(String authorization) {
   String accessToken = null;
   
   if(authorization != null && authorization.startsWith("Bearer ")) {
     accessToken = authorization.substring(7);
   }
   
   return accessToken;
 }
  
 public static void main(String[] args) throws Exception {
   String accessToken = createAccessToken("user", "ROLE_USER");
   System.out.println(validateToken(accessToken));
   
   Date expiration = getExpiration(accessToken);
   System.out.println(expiration);
   
   Map<String, String> userInfo = getUserInfo(accessToken);
   System.out.println(userInfo);   
 }
}
