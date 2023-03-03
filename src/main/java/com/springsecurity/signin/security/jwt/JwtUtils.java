package com.springsecurity.signin.security.jwt;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import io.jsonwebtoken.security.Keys;

import org.springframework.web.util.WebUtils;

import com.springsecurity.signin.security.services.UserDetailsImpl;

import io.jsonwebtoken.*;

@Component
public class JwtUtils {
	 private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

	  @Value("${application.jwtSecret}")
	  private String jwtSecret;

	  @Value("${application.jwtExpirationMs}")
	  private int jwtExpirationMs;

	  @Value("${application.jwtCookieName}")
	  private String jwtCookie;
	 

	  public String getJwtFromCookies(HttpServletRequest request) {
	    Cookie cookie = WebUtils.getCookie(request, jwtCookie);
	    if (cookie != null) {
	      return cookie.getValue();
	    } else {
	      return null;
	    }
	  }

	  public ResponseCookie generateJwtCookie(UserDetailsImpl userPrincipal) {
		    String jwt = generateTokenFromUsername(userPrincipal.getUsername());
		    ResponseCookie cookie = ResponseCookie.from(jwtCookie, jwt).path("/api").maxAge(24 * 60 * 60).httpOnly(true).build();
		    return cookie;
		  }

	  public ResponseCookie getCleanJwtCookie() {
	    ResponseCookie cookie = ResponseCookie.from(jwtCookie, null).path("/api/auth/**").build();
	    return cookie;
	  }

	  
	public String getUserNameFromJwtToken(String token) {
	    return Jwts.parserBuilder().setSigningKey(jwtSecret).build().parseClaimsJws(token).getBody().getSubject();
	  }

	  public boolean validateJwtToken(String authToken) {
		    try {
		      Jwts.parserBuilder().setSigningKey(jwtSecret).build().parseClaimsJws(authToken);
		      return true;
		    } catch (SignatureException e) {
		      logger.error("Invalid JWT signature: {}", e.getMessage());
		    } catch (MalformedJwtException e) {
		      logger.error("Invalid JWT token: {}", e.getMessage());
		    } catch (ExpiredJwtException e) {
		      logger.error("JWT token is expired: {}", e.getMessage());
		    } catch (UnsupportedJwtException e) {
		      logger.error("JWT token is unsupported: {}", e.getMessage());
		    } catch (IllegalArgumentException e) {
		      logger.error("JWT claims string is empty: {}", e.getMessage());
		    }

		    return false;
		  }
	  
	  private String generateSafeToken() {
		    SecureRandom random = new SecureRandom();
		    byte[] bytes = new byte[36]; // 36 bytes * 8 = 288 bits, a little bit more than
		                                 // the 256 required bits 
		    random.nextBytes(bytes);
		    var encoder = Base64.getUrlEncoder().withoutPadding();
		    return encoder.encodeToString(bytes);
		}
		  
		  public String generateTokenFromUsername(String username) {
			  
		    return Jwts.builder()
		        .setSubject(this.generateSafeToken())
		        .setIssuedAt(new Date())
		        .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
		        .signWith(Keys.secretKeyFor(SignatureAlgorithm.HS512), SignatureAlgorithm.HS512)
		        .compact();
		  }
		  
}
