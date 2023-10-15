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

    public ReferenceRequestDto(String cveId, String referenceUrl) {
        this.cveId = cveId;
        this.referenceUrl = referenceUrl;
    }

    public Reference toEntity() {
        return new Reference(this);
    }
}
