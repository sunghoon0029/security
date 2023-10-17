package com.project.security.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

import javax.persistence.Id;
import java.util.concurrent.TimeUnit;

@Getter
@RedisHash("refreshToken") // Redis DataBase에 refreshToken 관계 설정
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Token {

    @Id
    @JsonIgnore
    private Long id;

    private String refreshToken;

    @TimeToLive(unit = TimeUnit.SECONDS) // 데이터 유효기간 설정
    private Integer expiration;

    public void setExpiration(Integer expiration) {
        this.expiration = expiration;
    }
}
