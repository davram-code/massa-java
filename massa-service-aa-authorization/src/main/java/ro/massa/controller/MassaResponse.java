package ro.massa.controller;

import org.springframework.http.HttpStatus;

public class MassaResponse {
    byte[] content;
    HttpStatus httpStatus;

    public MassaResponse(byte[] content, HttpStatus status)
    {
        this.content = content;
        this.httpStatus = status;
    }

    public MassaResponse(byte[] content)
    {
        this.content = content;
        this.httpStatus = HttpStatus.OK;
    }

    byte []getContent()
    {
        return content;
    }

    HttpStatus getHttpStatus()
    {
        return httpStatus;
    }
}
