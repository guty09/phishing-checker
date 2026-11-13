package com.agguidigital.phishingchecker;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import com.agguidigital.phishingchecker.phishtank.PhishTankProperties;
import com.agguidigital.phishingchecker.virustotal.VirusTotalProperties;

@SpringBootApplication
@EnableConfigurationProperties({ VirusTotalProperties.class, PhishTankProperties.class })
public class PhishingCheckerApplication {

	public static void main(String[] args) {
		SpringApplication.run(PhishingCheckerApplication.class, args);
	}

}
