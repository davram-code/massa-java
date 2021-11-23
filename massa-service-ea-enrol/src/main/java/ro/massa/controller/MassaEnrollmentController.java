package ro.massa.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
    private static final Logger LOG = LoggerFactory.getLogger(MassaEnrollmentController.class);
    private @Autowired
    MassaEnrollmentService enrollmentService;

    @GetMapping(path = "/enrollment/probe")
    public String probeEnrollmentController() {
        LOG.debug("Massa Enrollment Controller is alive!");
        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

        return dateFormat.format(new Date());
    }

    @GetMapping(path = "/enrollment/reset")
    public String resetEnrollmentController() {
        LOG.debug("Massa Enrollment Controller is alive!");
        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        enrollmentService.reset();
        return dateFormat.format(new Date());
    }

    @PostMapping(path = "/enrollment")
    public ResponseEntity<byte[]> postEnrollmentRequest(@RequestBody byte[] base64Request) {
        LOG.debug("Enrollment request received");

        return new ResponseEntity<byte[]>(enrollmentService.verifyEnrolCertRequest(base64Request), HttpStatus.OK);
    }

    @GetMapping(path = "/enrollment") /* asta ar trebui facuta token-based -> ramane de discutat*/
    public ResponseEntity<String> getEnrollmentCertificate() {
        LOG.debug("Enrollment request received");

        return new ResponseEntity<>(enrollmentService.resolveEnrolCertRequest(), HttpStatus.OK);
    }
}
