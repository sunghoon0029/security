package com.project.security.service;

import com.project.security.dto.SignRequest;
import com.project.security.dto.SignResponse;
import com.project.security.dto.TokenDto;
import com.project.security.entity.Authority;
import com.project.security.entity.Member;
import com.project.security.jwt.JwtProvider;
import com.project.security.entity.Token;
import com.project.security.repository.MemberRepository;
import com.project.security.repository.TokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.UUID;

@Service
@Transactional
@RequiredArgsConstructor
public class SignService {

    private final MemberRepository memberRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    // 회원가입
    public boolean join(SignRequest request) throws Exception {
        try {
            Member member = Member.builder()
                    .email(request.getEmail())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .nickname(request.getNickname())
                    .build();

            member.setRoles(Collections.singletonList(Authority.builder().name("ROLE_USER").build())); // 사용자 권한(USER) 설정

            memberRepository.save(member);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            throw new Exception("잘못된 요청입니다.");
        }
        return true;
    }

    // 로그인
    public SignResponse login(SignRequest request) throws Exception {
        // 사용자 이메일 유효성 검증
        Member member = memberRepository.findByEmail(request.getEmail()).orElseThrow(() ->
                new BadCredentialsException("잘못된 계정정보입니다."));
        // 사용자 비밀번호 유효성 검증
        if (!passwordEncoder.matches(request.getPassword(), member.getPassword())) {
            throw new BadCredentialsException("잘못된 계정정보입니다.");
        }

        // 로그인 응답 구성
        return SignResponse.builder()
                .id(member.getId())
                .email(member.getEmail())
                .nickname(member.getNickname())
                .roles(member.getRoles())
                .token(TokenDto.builder() // Token 생성
                        .accessToken(jwtProvider.createToken(member.getEmail(), member.getRoles())) // Access Token 생성
                        .refreshToken(createRefreshToken(member)) // Refresh Token 생성
                        .build())
                .build();

    }

    // 이메일 주소를 통해 사용자 정보 조회
    public SignResponse findByEmail(String email) throws Exception {
        Member member = memberRepository.findByEmail(email)
                .orElseThrow(() -> new Exception("계정을 찾을 수 없습니다."));
        return new SignResponse(member);
    }

    /**
     * Refresh Token 생성
     * Redis 내부에는
     * refreshToken:memberId : tokenValue
     * 형태로 저장
     */
    // Refresh Token 생성
    public String createRefreshToken(Member member) {
        Token token = tokenRepository.save(
                Token.builder()
                        .id(member.getId())
                        .refreshToken(UUID.randomUUID().toString())
                        .expiration(120)
                        .build()
        );
        return token.getRefreshToken();
    }

    // Refresh Token 검증
    public Token validRefreshToken(Member member, String refreshToken) throws Exception {
        Token token = tokenRepository.findById(member.getId()).orElseThrow(() -> new Exception("만료된 계정입니다. 로그인을 다시 시도하세요."));
        if (token.getRefreshToken() == null) {
            return null;
        } else {
            if (token.getExpiration() < 10) {
                token.setExpiration(1000);
                tokenRepository.save(token);
            }

            if (!token.getRefreshToken().equals(refreshToken)) {
                return null;
            } else {
                return token;
            }
        }
    }

    public TokenDto refreshAccessToken(TokenDto token) throws Exception {
        String email = jwtProvider.getEmail(token.getAccessToken()); // Token에서 사용자 이메일 주소 추출
        Member member = memberRepository.findByEmail(email).orElseThrow(() -> // 추출한 이메일 주소를 기반으로 사용자 정보 조회
                new BadCredentialsException("잘못된 계정정보입니다."));
        Token refreshToken = validRefreshToken(member, token.getRefreshToken()); // Token 유효성 확인

        if (refreshToken != null) { // 유효한 Refresh Token이 있는 경우, 새로운 Access Token과 유효한 Refresh Token 반환
            return TokenDto.builder()
                    .accessToken(jwtProvider.createToken(email, member.getRoles()))
                    .refreshToken(refreshToken.getRefreshToken())
                    .build();
        } else {
            throw new Exception("로그인을 해주세요");
        }
    }
}
