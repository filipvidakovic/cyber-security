package org.cybersecurity.config.jwt;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {
    private final UserDetailsService jwtUserDetailsService;

    public JwtRequestFilter(@Lazy UserDetailsService jwtUserDetailsService) {
        this.jwtUserDetailsService = jwtUserDetailsService;
    }
    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (request.getRequestURI().equals("/api/auth/login") ||
                request.getRequestURI().equals("/api/auth/refresh")) {
            chain.doFilter(request, response);
            return;
        }
        else if (request.getRequestURL().toString().contains("/api/")) {
            System.out.println("#### " + request.getMethod() + ":" + request.getRequestURL());
            System.out.println("#### Authorization: " + request.getHeader("Authorization"));
            String requestTokenHeader = request.getHeader("Authorization");
            String username = null;
            String jwtToken = null;
            if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
                jwtToken = requestTokenHeader.substring(7).trim(); // get the actual token
                if (!jwtToken.isEmpty() && !"null".equals(jwtToken)) {
                    try {
                        username = jwtTokenUtil.extractUsername(jwtToken);
                        UserDetails userDetails = this.jwtUserDetailsService.loadUserByUsername(username);
                        if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
                            UsernamePasswordAuthenticationToken authToken =
                                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                            SecurityContextHolder.getContext().setAuthentication(authToken);
                            System.out.println("Auth OK: email={}, authorities={}"+ userDetails.getUsername()+ userDetails.getAuthorities());
                        }
                    } catch (IllegalArgumentException e) {
                        logger.warn("Unable to get JWT Token.");
                    } catch (TokenExpiredException ex) {
                        logger.info("JWT Token expired! Refreshing...");
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        response.getWriter().write("Token expired");
                        return;
                    } catch (JWTDecodeException ex) {
                        logger.warn("JWT Token is invalid: {}");
                    }
                } else {
                    logger.warn("JWT Token is empty or null string.");
                }
            } else {
                logger.warn("JWT Token does not exist.");
            }

        }
        chain.doFilter(request, response);
    }
}