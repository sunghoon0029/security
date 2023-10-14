package com.project.security.jwt;

import com.project.security.entity.Member;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.stream.Collectors;

// Spring Security는 사용자 인증과정에서 UserDetails를 참조하여 진행
// UserDetails를 상속받아 DB의 사용자 정보를 토대로 인증 설정
// Entity에 직접적으로 상속시 Entity가 오염되어 향후 Entity 사용리 어려워지기 때문에 CustomUserDetails를 따로 생성 후 관리
public class CustomUserDetails implements UserDetails {

    private final Member member;

    public CustomUserDetails(Member member) {
        this.member = member;
    }

    public final Member getMember() {
        return member;
    }

    // 사용자 역할 정보 Spring Security에게 제공
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return member.getRoles().stream().map(o -> new SimpleGrantedAuthority(
                o.getName()
        )).collect(Collectors.toList());
    }

    // 사용자 비밀번호 정보 Spring Security에게 제공
    @Override
    public String getPassword() {
        return member.getPassword();
    }

    // 사용자 이메일 정보 Spring Security에게 제공
    @Override
    public String getUsername() {
        return member.getEmail();
    }

    // 사용자의 계정 만료 여부
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 사용자의 계정 잠금상태 여부
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 사용자의 자격 증명 만료 여부
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 사용자의 계정 활성화 여부
    @Override
    public boolean isEnabled() {
        return true;
    }
}
