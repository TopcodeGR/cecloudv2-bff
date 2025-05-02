package com.ptopalidis.cecloud.bff;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@ComponentScan(basePackages = {
		"com.topcode.gateway",
})
@EnableJpaRepositories(basePackages = {
		"com.topcode.gateway",
})
@EntityScan(basePackages = {
		"com.topcode.gateway",
})
public class BffApplication {


	public static void main(String[] args) {
		SpringApplication.run(BffApplication.class, args);
	}

}
