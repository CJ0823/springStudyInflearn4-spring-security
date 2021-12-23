package io.security.basicsecurity;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;


@Configuration
@EnableWebSecurity  //WebSecurityConfiguration 등 웹 보안 활성화를 위한 여러 클래스들을 Import 해준다.
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests()  //요청에 대한 보안 설정을 시작함
                .anyRequest().authenticated();  //어떤 요청이든 authentication(인가) 과정을 거치도록 한다.

        http
                .formLogin();
    }
}
