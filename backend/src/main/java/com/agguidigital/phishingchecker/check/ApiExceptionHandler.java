package com.agguidigital.phishingchecker.check;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import jakarta.servlet.http.HttpServletRequest;

@RestControllerAdvice
public class ApiExceptionHandler {

	@ExceptionHandler({MethodArgumentNotValidException.class, HttpMessageNotReadableException.class})
	public ResponseEntity<ApiError> invalidRequest(HttpServletRequest request) {
		String path = request.getRequestURI();
		String code = path != null && path.startsWith("/api/email/") ? "invalid_text" : "invalid_url";
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ApiError(code));
	}

}
