package com.cos.security1.config;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableWebSecurity  // 스프링 시큐리티 필터가 스프링 필터 체인에 등록이 됨
//@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)  //secured 어노테이션 활성화, preAuthorize 어노테이션 활성화
@EnableMethodSecurity(securedEnabled = true) // @EnableGlobalMethodSecurity Deprecated 되어서 이거 사용!

public class SecurityConfig {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    //해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    //기존: WebSecurityConfigurerAdapter를 상속하고 configure매소드를 오버라이딩하여 설정하는 방법
    //=> 현재: SecurityFilterChain을 리턴하는 메소드를 빈에 등록하는 방식(컴포넌트 방식으로 컨테이너가 관리)
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(CsrfConfigurer::disable);
        http.authorizeHttpRequests(authorize ->
                        authorize.requestMatchers("/user/**").authenticated()  //인증만 되면 들어갈 수 있는 주소
                                .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")
                                .requestMatchers("/admin/**").hasAnyRole("ADMIN")

                                .anyRequest().permitAll()
                )
                .formLogin(form ->
                        form.loginPage("/loginForm")
                                .loginProcessingUrl("/login")  // /login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인 진행해줌
                                .defaultSuccessUrl("/")
                )
                .oauth2Login(oauth2 ->
                        oauth2.loginPage("/loginForm")
                                .userInfoEndpoint(userInfo -> userInfo
                                        .userService(principalOauth2UserService)
                                )

                );

        return http.build();
    }


}

//oauth
//1. 코드 받기(인증), 2. 엑세스 토큰(권한),
//3. 사용자 프로필 정보를 가져오고 4. 정보를 토대로 자동으로 진행시킴
//-> oauth client로
// 코드X, (액세스 토큰 + 사용자 프로필 정보)O
