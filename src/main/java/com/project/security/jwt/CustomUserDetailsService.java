package com.project.security.jwt;

import com.project.security.entity.Member;
import com.project.security.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// UserDetailsService는 UserDetails 정보를 토대로 사용자 정보를 불러올 때 사용
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private MemberRepository memberRepository;

    // 주어진 사용자 이름(이메일)을 기반으로 사용자 정보를 검색하고 Spring Security에게 반환
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Member member = memberRepository.findByEmail(username).orElseThrow(
                () -> new UsernameNotFoundException("Invalid authentication!")
        );

        return new CustomUserDetails(member);
    }
}
