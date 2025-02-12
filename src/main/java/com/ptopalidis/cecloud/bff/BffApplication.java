package com.ptopalidis.cecloud.bff;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = {
		"com.topcode.gateway",
})
public class BffApplication {


	public static void main(String[] args) {
		SpringApplication.run(BffApplication.class, args);
	}

}
