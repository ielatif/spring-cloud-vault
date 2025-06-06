/*
 * Copyright 2017-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.cloud.vault.config;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.vault.util.VaultRule;
import org.springframework.vault.core.ReactiveVaultOperations;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test using config infrastructure with token authentication.
 *
 * <p>
 * In case this test should fail because of SSL make sure you run the test within the
 * spring-cloud-vault-config/spring-cloud-vault-config directory as the keystore is
 * referenced with {@code ../work/keystore.jks}.
 *
 * @author Mark Paluch
 */

@SpringBootTest(classes = ReactiveVaultOperationsTests.TestApplication.class,
		properties = { "spring.cloud.vault.host=foo", "spring.cloud.vault.uri=https://localhost:8200",
				"spring.cloud.bootstrap.enabled=true" })
public class ReactiveVaultOperationsTests {

	@Autowired
	ReactiveVaultOperations reactiveOperations;

	@BeforeAll
	public static void beforeClass() {

		VaultRule vaultRule = new VaultRule();
		vaultRule.before();

		Map<String, Object> object = new HashMap<>();
		object.put("vault.value", "foo");
		object.put("nested", Collections.singletonMap("key", "value"));

		vaultRule.prepare().getVaultOperations().write("secret/testVaultApp", object);
	}

	@Test
	public void shouldAccessVault() {

		StepVerifier.create(this.reactiveOperations.read("secret/testVaultApp")).consumeNextWith(actual -> {
			assertThat(actual.getData()).containsEntry("vault.value", "foo");
		}).verifyComplete();
	}

	@SpringBootApplication
	public static class TestApplication {

		public static void main(String[] args) {
			SpringApplication.run(TestApplication.class, args);
		}

	}

}
