package me.jjw.tutorial.Config;

import lombok.RequiredArgsConstructor;
import me.jjw.tutorial.jwt.JwtAccessDeniedHandler;
import me.jjw.tutorial.jwt.JwtAuthenticationEntryPoint;
import me.jjw.tutorial.jwt.JwtSecurityConfig;
import me.jjw.tutorial.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity //웹 보안 활성화
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers(
                "/favicon.ico", "/h2-console", "/h2-console/**");
    }
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()

                .headers().frameOptions().sameOrigin().and()

                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                        .accessDeniedHandler(jwtAccessDeniedHandler))

                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/api/hello","/api/authenticate","/api/signup").permitAll()
                        .anyRequest().authenticated())

                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .httpBasic(Customizer.withDefaults())

                .apply(new JwtSecurityConfig(tokenProvider));

        return http.build();
    }
}
