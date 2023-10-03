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

    public static CommonResponse resWithoutData (final String responseCode, final String responseMessage) {
        return CommonResponse.builder()
                .responseCode(responseCode)
                .responseMessage(responseMessage)
                .build();
    }
    public static <T> CommonResponse<T> resWithData (final String responseCode, final String responseMessage, final T data) {
        return CommonResponse.<T>builder()
                .responseCode(responseCode)
                .responseMessage(responseMessage)
                .data(data)
                .build();
    }
}
