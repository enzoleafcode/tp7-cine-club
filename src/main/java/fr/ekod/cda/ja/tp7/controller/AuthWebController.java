package fr.ekod.cda.ja.tp7.controller;

import fr.ekod.cda.ja.tp7.dto.auth.LoginRequestDTO;
import fr.ekod.cda.ja.tp7.dto.auth.RegisterRequestDTO;
import fr.ekod.cda.ja.tp7.security.CustomUserDetailsService;
import fr.ekod.cda.ja.tp7.security.JwtService;
import fr.ekod.cda.ja.tp7.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class AuthWebController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService userDetailsService;
    private final JwtService jwtService;

    @GetMapping("/register")
    public String showRegisterForm(Model model) {
        model.addAttribute("registerForm", new RegisterRequestDTO(null, null, null, null));
        return "auth/register";
    }

    @PostMapping("/register")
    public String register(RegisterRequestDTO registerForm) {
        userService.register(registerForm);
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String showLoginForm(Model model) {
        model.addAttribute("loginForm", new LoginRequestDTO(null, null));
        return "auth/login";
    }

    @PostMapping("/login")
    public String login(LoginRequestDTO loginForm, HttpServletResponse response) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginForm.email(), loginForm.password())
        );

        UserDetails userDetails = userDetailsService.loadUserByUsername(loginForm.email());
        String accessToken = jwtService.generateAccessToken(userDetails);

        Cookie jwtCookie = new Cookie("ACCESS_TOKEN", accessToken);
        jwtCookie.setHttpOnly(true);
        jwtCookie.setPath("/");

        response.addCookie(jwtCookie);

        return "redirect:/";
    }

    @GetMapping("/logout")
    public String logout(HttpServletResponse response) {
        Cookie cookie = new Cookie("ACCESS_TOKEN", "");
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
        return "redirect:/";
    }
}