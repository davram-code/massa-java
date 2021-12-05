package ro.massa.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ro.massa.service.MassaRootService;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

@RestController
@RequestMapping("/massa")
public class MassaRootController {
    private @Autowired
    MassaRootService massaRootService;

    @GetMapping(path = "/root/probe")
    public String probeRootController() {
        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

        return dateFormat.format(new Date());
    }

    @GetMapping(path = "/selfcert")
    public ResponseEntity<byte[]> getSelfSignedCertificate() {
        return new ResponseEntity<byte[]>(massaRootService.getSelfSignedCertificate(), HttpStatus.OK);
    }
    //public ResponseEntity<byte[]> postEaCertificateRequest(@RequestBody byte[] base64Request) {
    @PostMapping(path = "/certify/ea")
    public ResponseEntity<byte[]> postEaCertificateRequest(@RequestBody byte[] request) {

        return new ResponseEntity<byte[]>(massaRootService.certifyEnrollmentCA(request), HttpStatus.OK);
    }


    @PostMapping(path = "/certify/aa")
    public ResponseEntity<byte[]> postAaCertificateRequest(@RequestBody byte[] request) {

        return new ResponseEntity<byte[]>(massaRootService.certifyAuthorizationCA(request), HttpStatus.OK);
    }

    @GetMapping(path = "/revoke/{hash}")
    public String revokeCertificate(@PathVariable("hash") String hash) {
        return massaRootService.revokeCertificate(hash);
    }
}
