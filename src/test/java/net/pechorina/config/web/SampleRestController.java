package net.pechorina.config.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SampleRestController {
    private final Logger log = LoggerFactory.getLogger(SampleRestController.class);

    @GetMapping("/api/test1")
    @PreAuthorize("hasAnyAuthority('OP_TESTROLE1')")
    public ResponseEntity<Void> test1() {
        log.debug("SecurityContext: {}", SecurityContextHolder.getContext().getAuthentication());
        return ResponseEntity.ok().build();
    }

    @GetMapping("/public1")
    public ResponseEntity<Void> public1() {
        log.debug("SecurityContext: {}", SecurityContextHolder.getContext().getAuthentication());
        return ResponseEntity.ok().build();
    }
}
