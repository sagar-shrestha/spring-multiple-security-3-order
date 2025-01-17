package com.sagar.baseproject.security.controller;

import com.sagar.baseproject.common.pojo.response.GlobalApiResponse;
import com.sagar.baseproject.security.entity.UserInfo;
import com.sagar.baseproject.security.service.UserInfoService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/super")
@RequiredArgsConstructor
public class UserInfoController {

    private final UserInfoService userInfoService;
   // private final BCryptPasswordEncoder bCryptPasswordEncoder;

  //  @PreAuthorize("hasAuthority('SUPER_SUPER')")
    @PostMapping
    public ResponseEntity<GlobalApiResponse> saveUserInfo(@RequestBody UserInfo userInfo) {
        String password = userInfo.getPassword();
      //  userInfo.setPassword(bCryptPasswordEncoder.encode(password));
        userInfoService.saveUserInfo(userInfo);
        return ResponseEntity.ok(GlobalApiResponse.builder()
                .code(HttpStatus.CREATED.value())
                .data(null)
                .message("User Created Successfully")
                .status(true)
                .build());
    }
}
