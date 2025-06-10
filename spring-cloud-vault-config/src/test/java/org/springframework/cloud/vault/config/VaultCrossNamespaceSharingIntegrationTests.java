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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.assertj.core.api.Assertions;
import org.junit.ClassRule;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.vault.util.Settings;
import org.springframework.cloud.vault.util.TestRestTemplateFactory;
import org.springframework.cloud.vault.util.VaultRule;
import org.springframework.test.context.TestPropertySource;
import org.springframework.vault.VaultException;
import org.springframework.vault.authentication.SimpleSessionManager;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.ClientHttpRequestFactoryFactory;
import org.springframework.vault.client.RestTemplateBuilder;
import org.springframework.vault.client.VaultHttpHeaders;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.ClientOptions;
import org.springframework.vault.support.VaultResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration test using config infrastructure with TLS certificate authentication for
 * Cross Namespace Sharing. In case this test should fail because of SSL make sure you run
 * the test within the spring-cloud-vault-config/spring-cloud-vault-config directory as
 * the keystore is referenced with {@code ../work/keystore.jks}.
 * <p>
 * Test scenario is inspired by this tutorial from HashiCorp <a href=
 * "https://developer.hashicorp.com/vault/tutorials/enterprise/namespaces-secrets-sharing#scenario-setup">Manage
 * secrets across namespaces</a>
 *
 * @author Mark Paluch
 * @author Issam El-atif
 */

@SpringBootTest(classes = VaultCrossNamespaceSharingIntegrationTests.TestApplication.class,
		properties = { "spring.cloud.vault.authentication=cert",
				"spring.cloud.vault.ssl.key-store=file:../work/client-cert.jks",
				"spring.cloud.vault.ssl.key-store-password=changeit", "spring.cloud.vault.namespace=us-west-org",
				"spring.cloud.vault.reactive.enabled=false", "spring.cloud.bootstrap.enabled=true" })
public class VaultCrossNamespaceSharingIntegrationTests {

	@ClassRule
	public static VaultRule vaultRule = new VaultRule();

	@BeforeAll
	static void setup() throws IOException {

		assumeTrue(vaultRule.prepare().getVersion().isEnterprise(), "Namespaces require enterprise version");

		VaultOperations vaultOperations = vaultRule.prepare().getVaultOperations();

		// ---------------------------------
		// 1. Enable cross-namespace sharing
		// ---------------------------------
		vaultOperations.write("sys/config/group-policy-application", Map.of("group_policy_application_mode", "any"));

		// -------------------------------
		// 2. Create namespaces
		// -------------------------------
		List<String> namespaces = new ArrayList<>(Arrays.asList("us-west-org/", "us-east-org/"));
		List<String> list = vaultRule.prepare().getVaultOperations().list("sys/namespaces");
		namespaces.removeAll(list);
		for (String namespace : namespaces) {
			vaultOperations.write("sys/namespaces/" + namespace.replaceAll("/", ""));
		}

		// -------------------------------
		// 3. Setup us-west-org namespace
		// -------------------------------
		VaultTemplate westTemplate = vaultTemplate("us-west-org");

		// Enable kv-customer-info
		westTemplate.delete("sys/mounts/kv-customer-info");
		westTemplate.write("sys/mounts/kv-customer-info", Map.of("type", "kv", "options", Map.of("version", "2")));

		// Store secret
		westTemplate.write("kv-customer-info/data/customer-001",
				Map.of("data", Map.of("name", "Example LLC", "contact_email", "admin@example.com")));

		// Policy
		westTemplate.write("sys/policies/acl/customer-info-read-only", Map.of("policy", """
				path "kv-customer-info/data/*" {
					capabilities = ["read"]
				}
				"""));

		// Enable cert auth
		westTemplate.delete("sys/auth/cert");
		westTemplate.write("sys/auth/cert", Map.of("type", "cert"));

		// Upload cert role for CN-based login
		String TEST_CLIENT_CERT_PEM = Files.readString(Path.of("../work/ca/certs/client.cert.pem"));
		if (westTemplate.read("auth/cert/certs/tam-cert-role") == null) {
			westTemplate.write("auth/cert/certs/tam-cert-role", Map.of("certificate", TEST_CLIENT_CERT_PEM, "policies",
					"customer-info-read-only", "display_name", "tam-cert-role", "ttl", "1h"));
		}

		// Create Vault identity entity
		VaultResponse entityResp = westTemplate.read("identity/entity/name/TAM");
		if (entityResp == null) {
			entityResp = westTemplate.write("identity/entity", Map.of("name", "TAM"));
		}
		String entityId = (String) entityResp.getData().get("id");

		// Get cert mount accessor
		Map<String, Object> auths = westTemplate.read("sys/auth").getData();
		String accessor = auths.entrySet()
			.stream()
			.filter(e -> e.getKey().startsWith("cert/"))
			.map(e -> ((Map<?, ?>) e.getValue()).get("accessor"))
			.findFirst()
			.orElseThrow()
			.toString();

		// Create cert alias (maps CN to entity)
		if (westTemplate.read("identity/lookup/entity-alias/name/tam-cert-role") == null) {
			westTemplate.write("identity/entity-alias", Map.of("name", "client", // Certificate
																					// CN=client
					"canonical_id", entityId, "mount_accessor", accessor));
		}

		// -------------------------------
		// 4. Setup us-east-org namespace
		// -------------------------------
		VaultTemplate eastTemplate = vaultTemplate("us-east-org");

		// Enable kv-marketing
		eastTemplate.delete("sys/mounts/kv-marketing");
		eastTemplate.write("sys/mounts/kv-marketing", Map.of("type", "kv", "options", Map.of("version", "2")));

		// Store marketing secret
		eastTemplate.write("kv-marketing/data/campaign", Map.of("data", Map.of("start_date", "March 1, 2023",
				"end_date", "March 31, 2023", "prise", "Certification voucher", "quantity", "100")));

		// Create policy
		eastTemplate.write("sys/policies/acl/marketing-read-only", Map.of("policy", """
				path "kv-marketing/data/campaign" {
					capabilities = ["read"]
				}
				"""));

		// Create group
		eastTemplate.write("identity/group",
				Map.of("name", "campaign-admin", "policies", "marketing-read-only", "member_entity_ids", entityId));
	}

	private static VaultTemplate vaultTemplate(String namespace) {
		RestTemplateBuilder restTemplateBuilder = RestTemplateBuilder.builder()
			.requestFactory(
					ClientHttpRequestFactoryFactory.create(new ClientOptions(), Settings.createSslConfiguration()))
			.endpoint(TestRestTemplateFactory.TEST_VAULT_ENDPOINT)
			.defaultHeader(VaultHttpHeaders.VAULT_NAMESPACE, namespace);

		return new VaultTemplate(restTemplateBuilder,
				new SimpleSessionManager(new TokenAuthentication(Settings.token().getToken())));
	}

	@Nested
	@TestPropertySource(properties = { "spring.cloud.vault.cross-namespace-sharing.enabled=true",
			"spring.config.import=vault://us-west-org/kv-customer-info/customer-001?prefix=west., "
					+ "vault://us-east-org/kv-marketing/campaign?prefix=east." })
	class CrossNamespaceSharingEnabledTests {

		@Value("${west.name}")
		String name;

		@Value("${east.prise}")
		String prise;

		@Test
		void contextLoads() {
			assertThat(this.name).isEqualTo("Example LLC");
			assertThat(this.prise).isEqualTo("Certification voucher");
		}

	}

	@Nested
	@TestPropertySource(properties = { "spring.cloud.vault.cross-namespace-sharing.enabled=false",
			"spring.config.import=vault://kv-customer-info/customer-001?prefix=west." })
	class CrossNamespaceSharingDisabledTests {

		@Value("${west.name}")
		String name;

		@Autowired
		VaultTemplate vaultTemplate;

		@Test
		void canReadSecretFromMainNamespace() {
			assertThat(this.name).isEqualTo("Example LLC");
		}

		@Test
		void canNotReadSecretFromAnotherNamespace() {
			Assertions.assertThatThrownBy(() -> vaultTemplate.read("us-east-org/kv-marketing/data/campaign"))
				.isInstanceOf(VaultException.class)
				.hasMessageStartingWith("Status 403 Forbidden [us-east-org/kv-marketing/data/campaign]");
		}

	}

	@SpringBootApplication
	public static class TestApplication {

		public static void main(String[] args) {
			SpringApplication.run(TestApplication.class, args);
		}

	}

}
