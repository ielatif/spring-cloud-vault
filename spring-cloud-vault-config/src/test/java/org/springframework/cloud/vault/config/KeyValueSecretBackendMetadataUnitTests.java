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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link KeyValueSecretBackendMetadata}.
 *
 * @author Mark Paluch
 */
public class KeyValueSecretBackendMetadataUnitTests {

	VaultKeyValueBackendProperties properties = new VaultKeyValueBackendProperties();

	@Test
	public void shouldCreateDefaultContexts() {

		List<String> contexts = KeyValueSecretBackendMetadata.buildContexts(this.properties, Collections.emptyList());

		assertThat(contexts).hasSize(1).contains("application");
	}

	@Test
	public void shouldCreateDefaultForAppNameAndDefaultContext() {

		this.properties.setApplicationName("my-app");

		List<String> contexts = KeyValueSecretBackendMetadata.buildContexts(this.properties, Collections.emptyList());

		assertThat(contexts).hasSize(2).containsSequence("my-app", "application");
	}

	@Test
	public void shouldCreateDefaultForAppNameAndDefaultContextWithProfiles() {

		this.properties.setApplicationName("my-app");

		List<String> contexts = KeyValueSecretBackendMetadata.buildContexts(this.properties,
				Arrays.asList("cloud", "local"));

		assertThat(contexts).hasSize(6)
			.containsSequence("my-app/local", "my-app/cloud", "my-app", "application/local", "application/cloud",
					"application");
	}

	@Test
	public void shouldCreateAppNameContextIfDefaultIsDisabled() {

		this.properties.setApplicationName("my-app");
		this.properties.setDefaultContext("");

		List<String> contexts = KeyValueSecretBackendMetadata.buildContexts(this.properties, Collections.emptyList());

		assertThat(contexts).hasSize(1).containsSequence("my-app");
	}

	@Test
	public void shouldCreateContextsForCommaSeparatedAppName() {

		this.properties.setApplicationName("foo,bar");

		List<String> contexts = KeyValueSecretBackendMetadata.buildContexts(this.properties, Collections.emptyList());

		assertThat(contexts).hasSize(3).containsSequence("bar", "foo", "application");
	}

	@Test
	public void shouldCreateContextsWithProfile() {

		this.properties.setApplicationName("foo,bar");

		List<String> contexts = KeyValueSecretBackendMetadata.buildContexts(this.properties,
				Arrays.asList("cloud", "local"));

		assertThat(contexts).hasSize(9)
			.containsSequence("bar/local", "bar/cloud", "bar", "foo/local", "foo/cloud", "foo", "application/local",
					"application/cloud", "application");
	}

}
