package com.sp.sec.basic.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    UserDetailsService users() {
        UserDetails user1 = User.builder()
                // Security는 기본 인코더로 password를 인코딩을 하기 때문에 실제비밀번호를 인코더에 담아서 인코딩해야한다.
                .username("user1").password(passwordEncoder().encode("1234"))
                .roles("USER")
                .build();

        UserDetails admin = User.builder()
                .username("admin").password(passwordEncoder().encode("1234"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user1, admin);
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(); // 패스워드 인코더로 BCryptPasswordEncoder 사용
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .formLogin(config -> {
                    config.loginPage("/login")
//                            .successForwardUrl("/") // requestCache
                            .failureForwardUrl("/login?error=true");
                })
                .authorizeRequests(config -> {
                    config.antMatchers("/login").permitAll() // 로그인 페이지는 누구나 접근 허용
                            .antMatchers("/").authenticated(); // 홈페이지는 인증된 사용자만 접근 허용
                });

    }
}
