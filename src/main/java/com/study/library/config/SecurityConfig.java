package com.study.library.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity // 기존세팅 따라가지말고 밑에세팅 따라가라
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests() // 요청 인증 절차
                .antMatchers("/server/**", "/auth/**") // 요청 인증 받지말고 요청주소창 띄워라
                .permitAll() // 전부 허용해라
                .anyRequest() // 나머지 요청들은
                .authenticated(); // 인증 받아야 됨
    }
}
