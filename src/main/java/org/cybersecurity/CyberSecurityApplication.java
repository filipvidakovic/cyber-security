package org.cybersecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableAsync
@EnableScheduling
@SpringBootApplication
@EntityScan(basePackages = "org.cybersecurity.model")
public class CyberSecurityApplication {
    public static void main(String[] args) {

        System.out.println("Starting cyber security application");
        SpringApplication.run(CyberSecurityApplication.class, args);
    }
}
