package ro.massa.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ro.massa.service.MassaAuthorizationService;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

@RestController
@RequestMapping("/massa")
public class MassaAuthorizationController {
    private @Autowired
    MassaAuthorizationService authorizationService;

    @GetMapping(path = "/authorization/probe")
    public String probeAuthorizationController() {
        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

        return dateFormat.format(new Date());
    }

    @GetMapping(path = "/authorization/reset")
    public String resetAuthorizationService() {
        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

        authorizationService.reset();
        return dateFormat.format(new Date());
    }

    @PostMapping(path = "/authorization")
    public ResponseEntity<byte[]> postAuthorizationRequest(@RequestBody byte[] base64Request) {

        return new ResponseEntity<byte[]>(authorizationService.resolveAuthorizationCertificateRequest(base64Request), HttpStatus.OK);
    }
}
