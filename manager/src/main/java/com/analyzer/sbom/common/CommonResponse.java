package com.analyzer.sbom.common;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Getter;

@Getter
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CommonResponse<T> {

    private String responseCode;
    private String responseMessage;
    private T data;

    @Builder
    private CommonResponse(String responseCode, String responseMessage, T data) {
        this.responseCode = responseCode;
        this.responseMessage = responseMessage;
        this.data = data;
    }

    public static CommonResponse from (final String responseCode) {
        return CommonResponse.builder()
                .responseCode(responseCode)
                .build();
    }
    public static <T> CommonResponse<T> from (final String responseCode, final T data) {
        return CommonResponse.<T>builder()
                .responseCode(responseCode)
                .data(data)
                .build();
    }
}
