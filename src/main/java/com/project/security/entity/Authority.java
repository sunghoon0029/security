package com.project.security.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Authority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @JsonIgnore
    private Long id;

    @Column
    private String name;

    @ManyToOne
    @JoinColumn(name = "member")
    @JsonIgnore // JSON 변환과정에서 객체에 포함되지 않음
    private Member member;

    public void setMember(Member member) {
        this.member = member;
    }
}
