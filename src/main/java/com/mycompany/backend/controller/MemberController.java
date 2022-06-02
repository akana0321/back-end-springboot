package com.mycompany.backend.controller;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.annotation.Resource;

import org.json.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.mycompany.backend.dto.Member;
import com.mycompany.backend.security.Jwt;
import com.mycompany.backend.service.MemberService;
import com.mycompany.backend.service.MemberService.JoinResult;
import com.mycompany.backend.service.MemberService.LoginResult;

import lombok.extern.log4j.Log4j2;

@RestController
@Log4j2
@RequestMapping("/member")
public class MemberController {
  @Resource
  private MemberService memberService;
  
  @Resource
  private PasswordEncoder passwordEncoder;
  
  @Resource
  private RedisTemplate<String, String> redisTemplate;
  
  // Front-End에서 많이 쓰는 방식
  @PostMapping("/join")
  public Map<String, Object> join(@RequestBody Member member) {
    // 계정 활성화
    member.setMenabled(true);
    // 비밀번호 암호화
    member.setMpassword(passwordEncoder.encode(member.getMpassword()));
    // 회원 가입 처리
    JoinResult joinResult = memberService.join(member);
    // 응답 내용 설정
    Map<String, Object> map = new HashMap<>();
    if(joinResult == JoinResult.SUCCESS) {
      map.put("result", "success");
    } else if(joinResult == JoinResult.DUPLICATED) {
      map.put("result", "duplicated");
    } else {
      map.put("result", "fail");
    }    
    return map;
  }

  @PostMapping("/login")
  public ResponseEntity<String> login(@RequestBody Member member) {
    /* 유효성 검사 기능 넣는게 좋긴 함 */
    log.info("실행");
    
    // mid와 mpassword가 없을 경우
    if(member.getMid() == null || member.getMpassword() == null) {
      // 에러 응답
      return ResponseEntity.status(401) // 401 에러: 인증 상의 문제
                           .body("mid or mpassword cannot be null");
    }
    
    // 로그인 결과 얻기
    LoginResult loginResult = memberService.login(member);
    
    if(loginResult != LoginResult.SUCCESS) {
      return ResponseEntity.status(401) // 401 에러: 인증 상의 문제
                           .body("mid or mpassword cannot be null");
    }
    
    Member dbMember = memberService.getMember(member.getMid());
    log.info(dbMember);
    String accessToken = Jwt.createAccessToken(member.getMid(), dbMember.getMrole());
    String refreshToken = Jwt.createRefreshToken(member.getMid(), dbMember.getMrole());
    
    // Redis에 저장
    ValueOperations<String, String> vo = redisTemplate.opsForValue();
    vo.set(accessToken, refreshToken, Jwt.REFRESH_TOKEN_DURATION, TimeUnit.MILLISECONDS);
    
    // 쿠키 생성
    String refreshTokenCookie = ResponseCookie.from("refreshToken", refreshToken)
                                              .httpOnly(true)
                                              .secure(false)
                                              .path("/")
                                              .maxAge(Jwt.REFRESH_TOKEN_DURATION/1000)
                                              .domain("localhost")
                                              .build()
                                              .toString();
    
    // 본문 생성
    String json = new JSONObject()
                       .put("accessToken", accessToken)
                       .put("mid", member.getMid())
                       .toString();
    
    // 응답 설정
    return ResponseEntity
                         .ok()  // 응답: 상태코드 200
                         // 응답 헤더 추가
                         .header(HttpHeaders.SET_COOKIE, refreshTokenCookie)
                         .header(HttpHeaders.CONTENT_TYPE, "application/json")
                         // 응답 바디 추가
                         .body(json);
  }
  
  @GetMapping("/refreshToken")
  public ResponseEntity<String> refreshToken(
      @RequestHeader("Authorization") String authorization,
      @CookieValue("refreshToken") String refreshToken) {
    /* 
     * 받은 AccessToken, RefreshToken을 비교하려면
     * 서버에서도 로그인할 때 생성된 Token을 어딘가에 저장하기는 해야 함
     * 1. 마지막에 보낸 AccessToken이 맞는지 검사
     * 2. 서버에서 보내준 RefreshToken이 맞는지 검사
     * 일단 맞다는 가정하에 작성
     *    ->> Redis에 저장하여 해결
     */
    
    // Access Token 얻기
    String accessToken = Jwt.getAccessToken(authorization);
    if(accessToken == null) {
      return ResponseEntity.status(401).body("no access token");
    }
    
    // RefreshToken 여부 확인
    if(refreshToken == null) {
      return ResponseEntity.status(401).body("no refresh token");
    }
    
    // 동일한 토큰인지 확인
    ValueOperations<String, String> vo = redisTemplate.opsForValue();
    String redisRefreshToken = vo.get(accessToken);
    // redisRefreshToken이 없다는 것은 accessToken이 잘못되었다는 것
    if(redisRefreshToken == null) {
      return ResponseEntity.status(401).body("invalid access token");
    }
    // 받은 refreshToken과 redis의 refreshToken이 다르면 잘못되었다는 것
    if(!refreshToken.equals(redisRefreshToken)) {
      return ResponseEntity.status(401).body("invalid refresh token");
    }
    if(!Jwt.validateToken(redisRefreshToken)) {
      return ResponseEntity.status(401).body("invalid refresh token");
    }
    
    // 새로운 AccessToken 생성
    Map<String, String> userInfo = Jwt.getUserInfo(refreshToken);
    String mid = userInfo.get("mid");
    String authority = userInfo.get("authority");
    String newAccessToken = Jwt.createAccessToken(mid, authority);
    
    // 기존 redis의 저장된 정보 삭제
    redisTemplate.delete(accessToken);
    
    // redis의 accessToken 갱신
    Date expiration = Jwt.getExpiration(refreshToken);
    vo.set(newAccessToken, refreshToken, expiration.getTime() - new Date().getTime(), TimeUnit.MILLISECONDS);
    
    // 응답 설정
    String json = new JSONObject()
                        .put("accessToken", newAccessToken)
                        .put("mid", mid)
                        .toString();
    
    return ResponseEntity.ok()
                         .header(HttpHeaders.CONTENT_TYPE, "application/json")
                         .body(json);
  }
  
  @GetMapping("/logout")
  public ResponseEntity<String> logout(@RequestHeader("Authorization") String authorization) {
    //AccessToken 얻기
    String accessToken = Jwt.getAccessToken(authorization);
    if(accessToken == null) {
      return ResponseEntity.status(401).body("invalid access token");
    }
    
    // Redis에 저장된 인증 정보 삭제
    redisTemplate.delete(accessToken);
    
    // RefreshToken 쿠키 삭제 - 어짜피 삭제할 거라 값은 빈 값을 줘도 됨
    String refreshTokenCookie = ResponseCookie.from("refreshToken", "")
                                              .httpOnly(true)
                                              .secure(false)
                                              .path("/")
                                              .maxAge(0)
                                              .domain("localhost")
                                              .build()
                                              .toString();
    
    // 응답 설정
    return ResponseEntity
                .ok()
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie)
                .body("success");
  }
}
