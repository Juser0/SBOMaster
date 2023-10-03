package com.analyzer.sbom.controller;

import com.analyzer.sbom.common.CommonResponse;
import com.analyzer.sbom.dto.response.SbomResponseDto;
import com.analyzer.sbom.service.SbomService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.List;

import static org.springframework.http.HttpStatus.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/sbom")
@Tag(name = "SBOM", description = "SBOM controller")
public class SbomController {

    private final SbomService sbomService;

    @GetMapping
    @Operation(summary = "SBOM Scan", description = "Scan Software Bill of Materials")
    public ResponseEntity<CommonResponse<JsonNode>> scanSBOM(@RequestParam String token, @RequestParam String projectId, @RequestParam String baseUrl) throws JsonProcessingException {
        JsonNode sbomResult = sbomService.scanVulnerability(token, projectId, baseUrl);
        return ResponseEntity.status(OK).body(CommonResponse.resWithData("SBOM_SCAN_COMPLETED", "SBOM 스캔이 완료되었습니다", sbomResult));
    }

    @GetMapping("/report")
    @Operation(summary = "Get SBOM Report", description = "Get Software Bill of Materials' security report")
    public ResponseEntity<CommonResponse<List<SbomResponseDto>>> getReport(@RequestParam String token, @RequestParam String projectId, @RequestParam String baseUrl) throws IOException {
        List<SbomResponseDto> sbomReport = sbomService.generateReport(token, projectId, baseUrl);
        return ResponseEntity.status(OK).body(CommonResponse.resWithData("SBOM_REPORT_GENERATED", "SBOM 보안 보고서가 생성되었습니다", sbomReport));
    }
}
