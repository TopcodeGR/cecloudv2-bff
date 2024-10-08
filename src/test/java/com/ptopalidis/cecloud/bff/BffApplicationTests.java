package com.ptopalidis.cecloud.bff;

import com.ptopalidis.cecloud.bff.properties.OidcProperties;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;

@ContextConfiguration
@TestPropertySource("classpath:application.properties")
@SpringBootTest
class BffApplicationTests {

	@Autowired
	OidcProperties oidcProperties;

	@Test
	void contextLoads() {

		return;
	}




}
