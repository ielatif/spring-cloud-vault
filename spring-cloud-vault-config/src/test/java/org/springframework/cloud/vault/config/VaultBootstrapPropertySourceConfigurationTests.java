/*
 * Copyright 2018-2021 the original author or authors.
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

import java.time.Duration;

import org.junit.jupiter.api.Test;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.vault.authentication.SessionManager;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.core.lease.LeaseEndpoints;
import org.springframework.vault.core.lease.SecretLeaseContainer;
import org.springframework.vault.support.LeaseStrategy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for {@link VaultBootstrapPropertySourceConfiguration}.
 *
 * @author Mark Paluch
 * @author Mårten Svantesson
 */
public class VaultBootstrapPropertySourceConfigurationTests {

	private ApplicationContextRunner contextRunner = new ApplicationContextRunner()
		.withConfiguration(AutoConfigurations.of(VaultBootstrapPropertySourceConfiguration.class));

	@Test
	public void shouldConfigureExpiryTimeoutsAndStrategy() {

		this.contextRunner
			.withUserConfiguration(MockSecretLeaseContainerConfiguration.class, MockVaultOperationsConfiguration.class)
			.withAllowBeanDefinitionOverriding(true)
			.withPropertyValues("spring.cloud.vault.kv.enabled=false",
					"spring.cloud.vault.config.lifecycle.expiry-threshold=5m",
					"spring.cloud.vault.config.lifecycle.min-renewal=6m",
					"spring.cloud.vault.config.lifecycle.lease-endpoints=Leases",
					"spring.cloud.vault.config.lifecycle.lease-strategy=retain-on-error",
					"spring.cloud.bootstrap.enabled=true")
			.run(context -> {

				SecretLeaseContainer container = context.getBean(SecretLeaseContainer.class);
				verify(container).setExpiryThreshold(Duration.ofMinutes(5));
				verify(container).setMinRenewal(Duration.ofMinutes(6));
				verify(container).setLeaseEndpoints(LeaseEndpoints.Leases);
				verify(container).setLeaseStrategy(LeaseStrategy.retainOnError());
			});
	}

	@Test
	public void shouldConfigureWithoutAuthentication() {

		this.contextRunner.withUserConfiguration(MockVaultOperationsConfiguration.class)
			.withAllowBeanDefinitionOverriding(true)
			.withPropertyValues("spring.cloud.vault.kv.enabled=true",
					"spring.cloud.vault.config.lifecycle.enabled=true", "spring.cloud.vault.authentication=NONE",
					"spring.cloud.bootstrap.enabled=true")
			.run(context -> {

				assertThat(context).doesNotHaveBean(SessionManager.class);
				assertThat(context).hasSingleBean(SecretLeaseContainer.class);
			});
	}

	@EnableConfigurationProperties(VaultProperties.class)
	@Configuration(proxyBeanMethods = false)
	private static class MockSecretLeaseContainerConfiguration {

		@Bean
		SecretLeaseContainer secretLeaseContainer(VaultProperties properties) {

			SecretLeaseContainer mock = mock(SecretLeaseContainer.class);
			VaultConfiguration.customizeContainer(properties.getConfig().getLifecycle(), mock);

			return mock;
		}

	}

	@EnableConfigurationProperties(VaultProperties.class)
	@Configuration(proxyBeanMethods = false)
	private static class MockVaultOperationsConfiguration {

		@Bean
		VaultOperations vaultOperations() {
			return mock(VaultOperations.class);
		}

		@Bean
		VaultBootstrapConfiguration.TaskSchedulerWrapper taskSchedulerWrapper() {
			return new VaultBootstrapConfiguration.TaskSchedulerWrapper(mock(ThreadPoolTaskScheduler.class));
		}

	}

}
