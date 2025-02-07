package com.cos.security1.config.oauth;

import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired
    public PrincipalOauth2UserService(BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Autowired
    private UserRepository userRepository;

    //구글로부터 받은 userRequest 데이터에 대한 후처리되는 함수
    //함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어짐
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("userRequest={}", userRequest);
        log.info("ClientRegistration={}", userRequest.getClientRegistration());  //registrationId로 어떤 OAuth로 로그인했는지 확인 가능
        log.info("AccessToken={}", userRequest.getAccessToken().getTokenValue());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        //구글 로그인 버튼 클릭 -> 구글 로그인창 -> 로그인 완료 -> code리턴(OAuth-Client라이브러리) -> Access Token 요청
        //userRequest정보 -> loadUser함수 호출 -> 구글로부터 회원 프로필 받아준다
        log.info("getAttributes={}", oAuth2User.getAttributes());

        String provider = userRequest.getClientRegistration().getClientId();  //google
        String providerId = oAuth2User.getAttribute("sub");
        String username = provider + "_" + providerId;  //google_121241
        String password = bCryptPasswordEncoder.encode("겟인데어");
        String email = oAuth2User.getAttribute("email");
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);

        if (userEntity == null){
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }else {

        }
        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
