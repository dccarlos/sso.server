package com.dccarlos.sso.server;

import java.security.Principal;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class UserController {

    @RequestMapping("/user/me")
    public Principal user(Principal principal) {
        log.info("Providing principal {}", principal);

        return principal;
    }
}