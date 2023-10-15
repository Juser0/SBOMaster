package com.analyzer.sbom.dto.response;

import com.analyzer.sbom.domain.Reference;
import lombok.Getter;

import javax.validation.constraints.NotBlank;

@Getter
public class ReferenceResponseDto {
    @NotBlank
    private Long id;

    @NotBlank
    private String cveId;

    @NotBlank
    private String referenceUrl;

    private ReferenceResponseDto(Reference reference) {
        this.id = reference.getId();
        this.cveId = reference.getCveId();
        this.referenceUrl = reference.getReferenceUrl();
    }

    public static ReferenceResponseDto from(Reference reference) {
        return new ReferenceResponseDto(reference);
    }
}
