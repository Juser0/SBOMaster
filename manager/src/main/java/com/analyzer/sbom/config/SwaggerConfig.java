package com.analyzer.sbom.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {
    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .components(new Components())
                .info(apiInfo());
    }

    private Info apiInfo() {
        return new Info()
                .title("SBOM Vulnerability Analyzer")
                .description("SBOM에서 확인 가능한 취약점에 대한 정보를 정리해주는 애플리케이션 명세입니다")
                .version("1.0.0");
    }
}
