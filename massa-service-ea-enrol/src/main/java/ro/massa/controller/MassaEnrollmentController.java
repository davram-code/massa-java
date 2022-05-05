package ro.massa.controller;

import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ro.massa.service.MassaEnrollmentService;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

@RestController
@RequestMapping("/massa")
public class MassaEnrollmentController {
    MassaLog log = MassaLogFactory.getLog(MassaEnrollmentController.class);
    private @Autowired
    MassaEnrollmentService enrollmentService;

    @GetMapping(path = "/enrollment/probe")
    public String probeEnrollmentController() {
        log.log("Massa Enrollment Controller is alive!");
        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

        return dateFormat.format(new Date());
    }

    @GetMapping(path = "/enrollment/reset")
    public String resetEnrollmentController() {
        log.log("Massa Enrollment Controller is alive!");
        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        enrollmentService.reset();
        return dateFormat.format(new Date());
    }

    @GetMapping(path = "/ea/request")
    public ResponseEntity<byte[]> getCertificateRequest() {
        log.log("Generating Certificate Request");
        return new ResponseEntity<byte[]>(enrollmentService.getCertificateRequest(), HttpStatus.OK);
    }

    @GetMapping(path = "/ea/rekey")
    public ResponseEntity<byte[]> getRekeyCertificateRequest() {
        return new ResponseEntity<byte[]>(enrollmentService.getRekeyCertificateRequest(), HttpStatus.OK);
    }

    @PostMapping(path = "/enrollment")
    public ResponseEntity<byte[]> postEnrollmentRequest(@RequestBody byte[] base64Request) {
        MassaResponse massaResponse = enrollmentService.resolveEnrollmentCredentialRequest(base64Request);
        return new ResponseEntity<byte[]>(massaResponse.getContent(), massaResponse.getHttpStatus());
    }
}
