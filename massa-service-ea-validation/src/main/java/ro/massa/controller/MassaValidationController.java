package ro.massa.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.service.MassaValidationService;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

@RestController
@RequestMapping("/massa")
public class MassaValidationController {
    MassaLog log = MassaLogFactory.getLog(MassaValidationController.class);
    private @Autowired
    MassaValidationService validationService;

    @GetMapping(path = "/validation/probe")
    public String probeValidationController() {
        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        return dateFormat.format(new Date());
    }

    @GetMapping(path = "/validation/reset")
    public String resetValidationController() {
        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        validationService.reset();
        return dateFormat.format(new Date());
    }

    @PostMapping(path = "/validation")
    public ResponseEntity<byte[]> postAuthorizationRequest(@RequestBody byte[] base64Request) {
        return new ResponseEntity<byte[]>(validationService.validateAuthorizationCertificateRequest(base64Request), HttpStatus.OK);
    }
}
