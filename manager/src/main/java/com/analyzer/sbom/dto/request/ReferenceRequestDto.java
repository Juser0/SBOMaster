package com.analyzer.sbom.dto.request;

import com.analyzer.sbom.domain.Reference;
import lombok.Getter;

import javax.validation.constraints.NotBlank;

@Getter
public class ReferenceRequestDto {
    @NotBlank
    private String cveId;

    @NotBlank
    private String referenceUrl;

    public Reference toEntity(ReferenceRequestDto requestDto) {
        return new Reference(requestDto);
    }
}
