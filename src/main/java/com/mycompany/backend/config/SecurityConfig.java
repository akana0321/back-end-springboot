package com.mycompany.backend.config;

import javax.annotation.Resource;

import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.mycompany.backend.security.JwtAuthenticationFilter;

import lombok.extern.log4j.Log4j2;

@EnableWebSecurity
@Log4j2
public class SecurityConfig extends WebSecurityConfigurerAdapter {
  @Resource
  private RedisTemplate<String, String> redisTemplate;
  
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    log.info("실행");
    // 1. 서버 세션 비활성화 - Spring Security는 Session 인증 기반이라 자동 실행됨
    // 2. JSESSIONID가 생성되지 않음
    http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    // 3. 폼 로그인이 비활성화(MPA 방식이라면 살려야 함)
    http.formLogin().disable();
    // 4. 사이트 간 요청 위조 방지 비활성화
    http.csrf().disable();
    // 5. 요청 경로 권한 설정 - /board/이하의 모든 경로는 인증된 사용자만 가능하고(로그인), 이외는 로그인 안해도 가능 
    http.authorizeRequests()
        .antMatchers("/board/**").authenticated()
        .antMatchers("/**").permitAll();
    // 6. CORS 설정(REST API면 반드시 설정 - 프론트와 REST API가 다른 도메인일 경우 접근 허용)
    // 다른 도메인의 자바 스크립트로 접근할 수 있도록 허용(MPA 방식에서는 할 필요 없음)
    http.cors();
    // JWT 인증 필터 추가 - 폼 인증 필터가 동작하기 전에 필터링을 해야 함(하지만 안쓰는 기능이라 저거 대신에 사용한다는 것)
    http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
  }
  
  public JwtAuthenticationFilter jwtAuthenticationFilter() {
    JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter();
    jwtAuthenticationFilter.setRedisTemplate(redisTemplate);
    return jwtAuthenticationFilter;
  }
  
  // DB에 있는 내용과 비교하는 역할, DB에서 무엇을 가져올 것인지 결정, PasswordEncoder를 어떤 것을 쓸 것인가
  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    log.info("실행");
    
    /* MPA 폼 인증 방식에서 사용(MPA 방식, JWT 인증 방식에서는 사용하지 않음)
    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    provider.setUserDetailsService(new CustomUserDetailsService());
    provider.setPasswordEncoder(passwordEncoder());
    auth.authenticationProvider(provider);*/
  }
  
  @Override
  public void configure(WebSecurity web) throws Exception {
    log.info("실행");
    
    DefaultWebSecurityExpressionHandler defaultWebSecurityExpressionHandler = new DefaultWebSecurityExpressionHandler();
    defaultWebSecurityExpressionHandler.setRoleHierarchy(roleHierarchyImpl());  // @Bean이 붙어있어 roleHierarchyImpl 이름인 관리객체를 사용한다는 뜻, 한 번만 실행됨   
    web.expressionHandler(defaultWebSecurityExpressionHandler);
    
    /* MPA 방식에서 Security를 정용하지 않는 경로 설정, SPA 방식에서는 아래 언급된 것들을 접근하지 않음
    web.ignoring()  // Security가 무시할 경로, permitAll()은 Security가 관여를 하여 허가하는 것(둘이 다름)
       .antMatchers("/images/**")
       .antMatchers("/css/**")
       .antMatchers("/js/**")
       .antMatchers("/bootstrap/**")
       .antMatchers("/jquery/**")
       .antMatchers("/favicon.ico");*/
  }
  
  @Bean
  public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    // return new BCryptPasswordEncoder(); // 앞으로 암호는 무조건 BCrypt만 사용할 경우
  }
  
  // 권한 등급 설정
  @Bean
  public RoleHierarchyImpl roleHierarchyImpl() {
     log.info("실행");
     RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();
     roleHierarchyImpl.setHierarchy("ROLE_ADMIN > ROLE_MANAGER > ROLE_USER");
     return roleHierarchyImpl;
  }
  
  // CORS 설정(REST API에서만 사용, MPA에서는 없어도 됨)
  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    log.info("실행");
      CorsConfiguration configuration = new CorsConfiguration();
      //모든 요청 사이트 허용(도메인이 들어감, abc.com, def.com 양식, *는 모든 도메인 허용 - 공공 API가 되버림, 보통 제한함)
      configuration.addAllowedOrigin("*");
      //모든 요청 방식 허용(GET, POST, PUT 같은 방식)
      configuration.addAllowedMethod("*");
      //모든 요청 헤더 허용(받아서 처리할 헤더)
      configuration.addAllowedHeader("*");
      //모든 URL 요청에 대해서 위 내용을 적용
      UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
      source.registerCorsConfiguration("/**", configuration);
      return source;
  }
}
