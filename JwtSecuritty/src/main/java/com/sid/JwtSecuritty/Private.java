package com.sid.JwtSecuritty;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

//to test protected endpoints
@RestController
public class Private {

    @GetMapping("/private")
    public String privateMethod() {
        return "private";
    }


}
