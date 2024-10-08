package com.ptopalidis.cecloud.bff;

import com.ptopalidis.cecloud.bff.properties.OidcClientProperties;
import com.ptopalidis.cecloud.bff.properties.OidcProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({OidcProperties.class, OidcClientProperties.class})
public class BffApplication {

	public static void main(String[] args) {
		SpringApplication.run(BffApplication.class, args);
	}

}
