/*
 * Copyright 2016-2021 the original author or authors.
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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.cloud.vault.util.IntegrationTestSupport;
import org.springframework.cloud.vault.util.Settings;
import org.springframework.cloud.vault.util.Version;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assume.assumeTrue;

/**
 * Integration tests for {@link VaultPropertySource}.
 *
 * @author Mark Paluch
 */
public class VaultPropertySourceIntegrationTests extends IntegrationTestSupport {

	@BeforeEach
	public void before() {
		prepare().getVaultOperations().write("secret/myapp", Collections.singletonMap("key", "value"));
	}

	@Test
	public void shouldReadValue() {

		VaultProperties vaultProperties = Settings.createVaultProperties();

		VaultPropertySource propertySource = new VaultPropertySource(
				new VaultConfigTemplate(prepare().getVaultOperations(), vaultProperties), false,
				KeyValueSecretBackendMetadata.create("secret", "myapp"));

		propertySource.init();

		assertThat(propertySource.getPropertyNames()).contains("key");
		assertThat(propertySource.getProperty("key")).isEqualTo("value");
	}

	@Test
	public void shouldReadVersionedValue() {

		assumeTrue(this.vaultRule.prepare().getVersion().isGreaterThanOrEqualTo(Version.parse("0.10.0")));

		this.vaultRule.prepare()
			.getVaultOperations()
			.write("versioned/data/testVaultApp",
					Collections.singletonMap("data", Collections.singletonMap("key", "value")));

		VaultProperties vaultProperties = Settings.createVaultProperties();

		VaultPropertySource propertySource = new VaultPropertySource(
				new VaultConfigTemplate(prepare().getVaultOperations(), vaultProperties), false,
				KeyValueSecretBackendMetadata.create("versioned", "testVaultApp"));

		propertySource.init();

		assertThat(propertySource.getPropertyNames()).contains("key");
		assertThat(propertySource.getProperty("key")).isEqualTo("value");
	}

}
