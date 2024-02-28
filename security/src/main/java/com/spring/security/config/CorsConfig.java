package com.spring.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry){
        //configuracion para rutas privadas
        registry.addMapping("/**")
                .allowedOrigins("http://localhost:8080")
                .allowedMethods("GET", "POST", "PUT","DELETE","OPTIONS")
                .allowedHeaders("Origin", "Content-Type","Accept", "Authorization" )
                .allowCredentials(true)
                .maxAge(3600);

        //configuracion para rutas publicas
        registry.addMapping("/auth/**")
                .allowedOrigins("http://localhost:8080")
                .allowedMethods("GET", "POST", "PUT","DELETE","OPTIONS")
                .allowedHeaders("Origin", "Content-Type","Accept", "Authorization" )
                .allowCredentials(false)
                .maxAge(3600);
    }
}
