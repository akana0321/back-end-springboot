package com.mycompany.backend.controller;

import java.net.URI;

import javax.servlet.http.HttpServletResponse;

import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.log4j.Log4j2;

/*
 * SpringBoot는 ErrorController를 구현하는 컨트롤러가 있으면
 * 이를 찾아 에러 매핑
 */

@RestController
@Log4j2
public class ErrorHandlerController implements ErrorController {
  @RequestMapping("/error")
  public ResponseEntity<String> error(HttpServletResponse response) {
    int status = response.getStatus();
    if(status == 404) {
      return ResponseEntity.status(HttpStatus.MOVED_PERMANENTLY).location(URI.create("/")).body("");
    } else {
      return ResponseEntity.status(status).body("");
    }
  }
}
