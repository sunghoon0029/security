package com.project.security.dto;

import com.project.security.entity.Authority;
import com.project.security.entity.Member;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SignResponse {

    private Long id;

    private String email;

    private String nickname;

    private List<Authority> roles = new ArrayList<>();

    private String token;

    public SignResponse(Member member) {
        this.id = member.getId();
        this.email = member.getEmail();
        this.nickname = member.getNickname();
        this.roles = member.getRoles();
    }
}
