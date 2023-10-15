package com.project.security.jwt;

import com.project.security.entity.Authority;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtProvider {

    // application.yml jwt.secret.key 설정값
    @Value("${jwt.secret.key}")
    private String salt;

    private Key secretKey;

    // Token 만료시간 설정
    private final long exp = 30 * 60 * 1000L;

    private final CustomUserDetailsService userDetailsService;

    // Secret Key 암호화
    @PostConstruct
    protected void init() {
        // application.yml에 설정한 secret key값을 바이트 배열로 변환 후, 이를 기반으로 HMAC-SHA알고리즘을 사용하여 암호화 된 비밀키(secretKey) 생성
        secretKey = Keys.hmacShaKeyFor(salt.getBytes(StandardCharsets.UTF_8));
    }

    // Token 생성
    public String createToken(String email, List<Authority> roles) {
        Claims claims = Jwts.claims().setSubject(email); // Claim 설정, Claim: JWT 내에 포함되는 점보
        claims.put("roles", roles); // roles Claim에 권한(roles) 정보 추가
        Date now = new Date(); // 현재 시간 정보
        return Jwts.builder()
                .setClaims(claims) // Claim 정보 설정
                .setIssuedAt(now) // Token 발행 시간 설정
                .setExpiration(new Date(now.getTime() + exp)) // Token 만료 시간 설정
                .signWith(secretKey, SignatureAlgorithm.HS256) // JWT 서명에 사용할 비밀키, 서명 알고리즘 설정
                .compact(); // JWT 생성, 반환
    }

    // Token에서 인증 정보 조회
    public Authentication getAuthentication(String token) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(this.getAccount(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    // Token에서 사용자 정보 추출
    public String getAccount(String token) {
        return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody().getSubject();
    }

    // Authorization Header를 통해 인증
    public String resolveToken(HttpServletRequest request) {
        return request.getHeader("Authorization");
    }

    // Token 검증
    public boolean validateToken(String token) {
        try {
            // Bearer 검증
            if (!token.substring(0, "BEARER ".length()).equalsIgnoreCase("BEARER ")) {
                return false;
            } else {
                token = token.split(" ")[1].trim();
            }
            Jws<Claims> claims = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token); // Token 서명 검증
            return !claims.getBody().getExpiration().before(new Date()); // Token 만료 시간 검증
        } catch (Exception e) {
            return false;
        }
    }
}
