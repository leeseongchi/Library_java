package com.study.library.security;

import lombok.Builder;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Builder
@Data
public class PrincipalUser implements UserDetails {
    private int userId;
    private String username;
    private String name;
    private String email;
    private List<SimpleGrantedAuthority> authorities;

    @Override
    // 권한
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return "";
    }

    // 계정 사용시간 만료
    // 하나라도 false라면 로그인이 안됨
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 계정 잠금
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 비밀변호 사용기간 만료
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 계정 비활성화
    @Override
    public boolean isEnabled() {
        return true;
    }
}
