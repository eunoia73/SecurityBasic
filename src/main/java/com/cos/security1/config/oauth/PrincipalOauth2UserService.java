package com.cos.security1.config.oauth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    //구글로부터 받은 userRequest 데이터에 대한 후처리되는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("userRequest={}", userRequest);
        log.info("ClientRegistration={}", userRequest.getClientRegistration());  //registrationId로 어떤 OAuth로 로그인했는지 확인 가능
        log.info("AccessToken={}", userRequest.getAccessToken().getTokenValue());
        //구글 로그인 버튼 클릭 -> 구글 로그인창 -> 로그인 완료 -> code리턴(OAuth-Client라이브러리) -> Access Token 요청
        //userRequest정보 -> loadUser함수 호출 -> 구글로부터 회원 프로필 받아준다
        log.info("getAttributes={}", super.loadUser(userRequest).getAttributes());

        OAuth2User oAuth2User = super.loadUser(userRequest);

        return super.loadUser(userRequest);
    }
}
