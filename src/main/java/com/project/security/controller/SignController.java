package com.project.security.controller;

import com.project.security.dto.SignRequest;
import com.project.security.dto.SignResponse;
import com.project.security.dto.TokenDto;
import com.project.security.service.SignService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class SignController {

    private final SignService memberService;

    @PostMapping(value = "/join")
    public ResponseEntity<Boolean> signup(@RequestBody SignRequest request) throws Exception {
        return new ResponseEntity<>(memberService.join(request), HttpStatus.OK);

    }

    @PostMapping(value = "/login")
    public ResponseEntity<SignResponse> signin(@RequestBody SignRequest request) throws Exception {
        return new ResponseEntity<>(memberService.login(request), HttpStatus.OK);
    }

    @GetMapping("/user/get")
    public ResponseEntity<SignResponse> getUser(@RequestParam String email) throws Exception {
        return new ResponseEntity<>(memberService.findByEmail(email), HttpStatus.OK);
    }

    @GetMapping("/admin/get")
    public ResponseEntity<SignResponse> getUserForAdmin(@RequestParam String email) throws Exception {
        return new ResponseEntity<>(memberService.findByEmail(email), HttpStatus.OK);
    }

    @GetMapping("/refresh")
    public ResponseEntity<TokenDto> refresh(@RequestBody TokenDto token) throws Exception {
        return new ResponseEntity<>(memberService.refreshAccessToken(token), HttpStatus.OK);
    }
}
