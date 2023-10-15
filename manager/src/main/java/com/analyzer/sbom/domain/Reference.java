package com.analyzer.sbom.domain;

import com.analyzer.sbom.dto.request.ReferenceRequestDto;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Getter
@Table(name = "reference_tb")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Reference {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "cve")
    private String cveId;

    @Column(name = "reference_url")
    private String referenceUrl;

    public Reference(ReferenceRequestDto requestDto) {
        this.cveId = requestDto.getCveId();
        this.referenceUrl = requestDto.getReferenceUrl();
    }
}
