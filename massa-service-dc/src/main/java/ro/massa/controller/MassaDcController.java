package ro.massa.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ro.massa.service.MassaDcService;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

@RestController
@RequestMapping("/massa")
public class MassaDcController {
    private @Autowired
    MassaDcService massaDcService;

    @GetMapping(path = "/root/probe")
    public String probeRootController() {
        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

        return dateFormat.format(new Date());
    }

    @GetMapping(path = "/getctl")
    public ResponseEntity<byte[]> getCertificateTrustList() {
        return new ResponseEntity<byte[]>(massaDcService.getCTL(), HttpStatus.OK);
    }

    @GetMapping(path = "/getcrl")
    public ResponseEntity<byte[]> getCertificateRevocationList() {
        return new ResponseEntity<byte[]>(massaDcService.getCRL(), HttpStatus.OK);
    }
}
