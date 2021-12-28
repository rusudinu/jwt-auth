package com.codingshadows.auth.controller;

import com.codingshadows.auth.model.AuthenticationRequest;
import com.codingshadows.auth.model.AuthenticationResponse;
import com.codingshadows.auth.model.User;
import com.codingshadows.auth.repository.UserRepository;
import com.codingshadows.auth.service.MyUserDetailsService;
import com.codingshadows.auth.util.JWTUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
public class UserController {
    private final JWTUtil jwtUtil;

    private final UserRepository userRepository;

    private final AuthenticationManager authenticationManager;

    private final JWTUtil jwtTokenUtil;

    private final MyUserDetailsService userDetailsService;

    BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

    public UserController(JWTUtil jwtUtil, UserRepository userRepository, AuthenticationManager authenticationManager, JWTUtil jwtTokenUtil, MyUserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.jwtTokenUtil = jwtTokenUtil;
        this.userDetailsService = userDetailsService;
    }

    @PostMapping(value = "/auth")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getEmail(), authenticationRequest.getPassword()) //TODO ENCRYPT THE PASSWORD HERE
            );
        } catch (BadCredentialsException e) {
            throw new Exception("Incorrect username or password");
        }

        final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getEmail());

        final String jwt = jwtTokenUtil.generateToken(userDetails);

        return ResponseEntity.ok(new AuthenticationResponse(jwt));
    }

    @PostMapping(value = "/register")
    public String registerUser(@RequestBody AuthenticationRequest authenticationRequest) {
        if (userRepository.findUserByEmail(authenticationRequest.getEmail()) != null)
            return "The user already exists.";

        User user = new User();
        user.setUserID(UUID.randomUUID().toString());
        user.setEmail(authenticationRequest.getEmail());
        user.setUsername(authenticationRequest.getEmail());
        user.setPassword(bCryptPasswordEncoder.encode(authenticationRequest.getPassword()));
        user.setEnabled(true);
        user.setAccountNonExpired(true);
        user.setAccountNonLocked(true);
        user.setCredentialsNonExpired(true);
        userRepository.save(user);
        return "The user was created.";
    }

    @GetMapping(value = "/bps/data/user/{JWT}")
    public User getUserFromJWTPV(@PathVariable String JWT) {
        return getUserFromJWT(JWT);
    }

    @GetMapping(value = "/data/user")
    public User getUserFromJWTQP(@RequestParam String JWT) {
        return getUserFromJWT(JWT);
    }

    public User getUserFromJWT(String JWT) {
        String email = jwtUtil.extractEmail(JWT);

        //noinspection DuplicatedCode
        if (email != null) {
            UserDetails userDetails = this.userDetailsService.loadUserByEmail(email);
            if (jwtUtil.validateToken(JWT, userDetails)) {
                return userRepository.findUserByEmail(email);
            }
        }
        return null;
    }
}
