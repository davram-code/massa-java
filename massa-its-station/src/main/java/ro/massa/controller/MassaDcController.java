package ro.massa.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ro.massa.service.MassaItsStation;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

@RestController
@RequestMapping("/massa/station")
public class MassaDcController {
    private @Autowired
    MassaItsStation massaItsStation;

    @GetMapping(path = "/probe")
    public String probeRootController() {
        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

        return dateFormat.format(new Date());
    }

    @GetMapping(path = "/test1")
    public ResponseEntity<String> test1() {
        return new ResponseEntity<String>(massaItsStation.test1(), HttpStatus.OK);
    }
}
