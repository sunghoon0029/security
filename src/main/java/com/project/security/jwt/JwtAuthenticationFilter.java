package com.project.security.jwt;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// JWT를 사용한 사용자 인증을 수행하기 위한 필터
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;

    public JwtAuthenticationFilter(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    // HTTP 요청에 대한 필터링 및 처리, 모든 HTTP 요청에 호출됨
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = jwtProvider.resolveToken(request); // 요청에서 Token 추출

        if (token != null && jwtProvider.validateToken(token)) { // Token 유효성 검사
            token = token.split(" ")[1].trim();
            Authentication auth = jwtProvider.getAuthentication(token); // 사용자 인증 정보 호출
            SecurityContextHolder.getContext().setAuthentication(auth); // SecurityContext에 인증 정보 설정
        }

        filterChain.doFilter(request, response);
    }
}
