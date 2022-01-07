package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;


@Configuration
@EnableWebSecurity  //WebSecurityConfiguration 등 웹 보안 활성화를 위한 여러 클래스들을 Import 해준다.
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()  //요청에 대한 보안 설정을 시작함
                .anyRequest().authenticated();  //어떤 요청이든 authentication(인가) 과정을 거치도록 한다.

        http
                .formLogin()
//                .loginPage("/loginPage")
                .defaultSuccessUrl("/")
                .failureUrl("/login")
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc")
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication : " + authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception : " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll(); //로그인 페이지는 누구나 접근이 가능하도록 설정함

        http
                .logout()
                .logoutUrl("/logout") //logout url 설정
                .logoutSuccessUrl("/login") //logout 시 이동할 url만 설정
                .addLogoutHandler(new LogoutHandler() { //logout이 성공했을 때 처리할 내용
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() { //logout 시 이동할 url 및 더 많은 로직 구현 가능
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login"); //로그아웃 시 로그인 할 수 있는 페이지로 이동하도록 처리한다.
                    }
                })
                .deleteCookies("remember-me");

        http
                .rememberMe()
                .rememberMeParameter("remember") //기본값은 remember-me, 화면에서 체크박스 체크 시 넘겨주는 이름값을 설정해준다.
                .tokenValiditySeconds(3600) //기본값은 14일
//                .alwaysRemember(true) //remember me 기능이 활성화되지 않아도 항상 실행된다.
                .userDetailsService(userDetailsService); //user 계정을 조회하기 위한 service이며 객체를 @Autowired 해옴

    }
}
