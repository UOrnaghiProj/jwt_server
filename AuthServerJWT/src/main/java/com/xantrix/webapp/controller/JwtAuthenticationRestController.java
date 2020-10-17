package com.xantrix.webapp.controller;

import java.util.Objects;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.xantrix.webapp.security.JwtTokenUtil;
 

@RestController
//@CrossOrigin(origins = "http://localhost:4200")
public class JwtAuthenticationRestController 
{

	@Value("${sicurezza.header}")
	private String tokenHeader;

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	@Autowired
	@Qualifier("customUserDetailsService")
	private UserDetailsService userDetailsService;
	
	private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationRestController.class);

	
	@PostMapping(value = "${sicurezza.uri}") //Parametro presente nel file application.yml
	public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtTokenRequest authenticationRequest)
			throws Exception 
	{
		logger.info("Autenticazione e Generazione Token");

		Authentication auth = authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());

		if (!(auth instanceof AnonymousAuthenticationToken)) {
			UserDetails userDetails = (UserDetails) auth.getPrincipal();

			final String token = jwtTokenUtil.generateToken(userDetails);
			logger.warn(String.format("Token %s", token));

			return ResponseEntity.ok(new JwtTokenResponse(token));

		}else {
			throw new Exception();
		}

	}

	@RequestMapping(value = "${sicurezza.uri}", method = RequestMethod.GET)
	public ResponseEntity<?> refreshAndGetAuthenticationToken(HttpServletRequest request) 
	{
		String authToken = request.getHeader(tokenHeader);
		final String token = authToken.substring(7);
		
		if (jwtTokenUtil.canTokenBeRefreshed(token)) 
		{
			String refreshedToken = jwtTokenUtil.refreshToken(token);
			
			return ResponseEntity.ok(new JwtTokenResponse(refreshedToken));
		} 
		else 
		{
			return ResponseEntity.badRequest().body(null);
		}
	}

	@ExceptionHandler({ AuthenticationException.class })
	public ResponseEntity<String> handleAuthenticationException(AuthenticationException e) 
	{
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
	}

	private Authentication authenticate(String username, String password) 
	{
		Authentication auth = null;
		
		Objects.requireNonNull(username);
		Objects.requireNonNull(password);

		try 
		{
			 auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
		} 
		catch (DisabledException e) 
		{
			logger.warn("UTENTE DISABILITATO");
			throw new AuthenticationException("UTENTE DISABILITATO", e);
		} 
		catch (BadCredentialsException e) 
		{
			logger.warn("CREDENZIALI NON VALIDE");
			throw new AuthenticationException("CREDENZIALI NON VALIDE", e);
		}
		return auth;
	}
}
