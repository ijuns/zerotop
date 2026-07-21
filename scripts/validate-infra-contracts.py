#!/usr/bin/env python3
"""Fail closed when private-registry or admission contracts drift."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


ROOT = Path(__file__).resolve().parents[1]


def documents(relative: str) -> list[dict[str, Any]]:
    with (ROOT / relative).open("r", encoding="utf-8") as stream:
        return [item for item in yaml.safe_load_all(stream) if isinstance(item, dict)]


def yaml_value(relative: str) -> Any:
    with (ROOT / relative).open("r", encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def resource(relative: str, kind: str, name: str) -> dict[str, Any]:
    for item in documents(relative):
        if item.get("kind") == kind and item.get("metadata", {}).get("name") == name:
            return item
    raise AssertionError(f"{relative} does not contain {kind}/{name}")


def named(items: list[dict[str, Any]], name: str) -> dict[str, Any]:
    for item in items:
        if item.get("name") == name:
            return item
    raise AssertionError(f"missing named entry: {name}")


def assert_registry_external_secrets() -> None:
    expected = {
        "codegate-build-registry": ("kubernetes.io/dockerconfigjson", {".dockerconfigjson"}),
        "codegate-validator-registry": ("kubernetes.io/dockerconfigjson", {".dockerconfigjson"}),
        "codegate-private-registry-ca": ("Opaque", {"ca.crt"}),
        "codegate-builder-signing": ("Opaque", {"cosign.key", "cosign.pub", "password"}),
    }
    docs = documents("infra/kubernetes/base/registry-external-secrets.yaml")
    assert {item["metadata"]["name"] for item in docs} == set(expected)
    for item in docs:
        name = item["metadata"]["name"]
        secret_type, keys = expected[name]
        spec = item["spec"]
        assert spec["secretStoreRef"] == {"kind": "SecretStore", "name": "codegate-platform-secrets"}
        assert spec["target"]["name"] == name
        assert spec["target"]["template"]["type"] == secret_type
        assert {entry["secretKey"] for entry in spec["data"]} == keys


def assert_application_external_secrets() -> None:
    platform_expected = {
        "codegate-api-secrets": {
            "DATABASE_URL", "REDIS_URL", "KEYCLOAK_CLIENT_SECRET", "RUNTIME_INTERNAL_TOKEN",
            "DESKTOP_GATEWAY_INTERNAL_TOKEN", "GRADER_INTERNAL_TOKEN", "AI_INTERNAL_TOKEN",
            "OPENVPN_DOWNLOAD_INTERNAL_TOKEN", "VALIDATOR_INTERNAL_TOKEN", "TELEMETRY_INTERNAL_TOKEN",
            "BUILDER_INTERNAL_TOKEN",
        },
        "codegate-ai-secrets": {
            "AI_INTERNAL_TOKEN", "GENERATION_PROVIDER_TOKEN", "REVIEW_PROVIDER_TOKEN", "RUBRIC_PROVIDER_TOKEN",
        },
        "codegate-builder-secrets": {"BUILDER_INTERNAL_TOKEN", "DATABASE_URL"},
        "codegate-grader-secrets": {"GRADER_INTERNAL_TOKEN", "ELASTICSEARCH_API_KEY", "AI_INTERNAL_TOKEN"},
        "codegate-validator-secrets": {"VALIDATOR_INTERNAL_TOKEN", "SANDBOX_RUNNER_INTERNAL_TOKEN", "AI_INTERNAL_TOKEN"},
        "codegate-validator-trust": {"cosign.pub"},
        "codegate-telemetry-secrets": {"TELEMETRY_INTERNAL_TOKEN", "ELASTICSEARCH_API_KEY"},
    }
    platform_docs = documents("infra/kubernetes/base/application-external-secrets.yaml")
    assert {item["metadata"]["name"] for item in platform_docs} == set(platform_expected)
    for item in platform_docs:
        name = item["metadata"]["name"]
        spec = item["spec"]
        assert spec["secretStoreRef"] == {"kind": "SecretStore", "name": "codegate-platform-secrets"}
        assert spec["target"]["name"] == name
        assert spec["target"]["creationPolicy"] == "Owner"
        assert spec["target"]["deletionPolicy"] == "Retain"
        assert {entry["secretKey"] for entry in spec["data"]} == platform_expected[name]

    ai_secret = next(item for item in platform_docs if item["metadata"]["name"] == "codegate-ai-secrets")
    ai_provider_entries = {
        entry["secretKey"]: entry["remoteRef"]
        for entry in ai_secret["spec"]["data"]
        if entry["secretKey"] in {"GENERATION_PROVIDER_TOKEN", "REVIEW_PROVIDER_TOKEN", "RUBRIC_PROVIDER_TOKEN"}
    }
    assert set(ai_provider_entries) == {"GENERATION_PROVIDER_TOKEN", "REVIEW_PROVIDER_TOKEN", "RUBRIC_PROVIDER_TOKEN"}
    assert all(ref == {"key": "codegate/production/internal/model-gateway", "property": "token"}
               for ref in ai_provider_entries.values())

    gateway_secret = resource(
        "infra/kubernetes/base/model-gateway-external-secret.yaml",
        "ExternalSecret",
        "codegate-model-gateway-secrets",
    )
    assert gateway_secret["spec"]["secretStoreRef"] == {"kind": "SecretStore", "name": "codegate-platform-secrets"}
    gateway_entries = {entry["secretKey"]: entry["remoteRef"] for entry in gateway_secret["spec"]["data"]}
    assert gateway_entries == {
        "MODEL_GATEWAY_INTERNAL_TOKEN": {"key": "codegate/production/internal/model-gateway", "property": "token"},
        "OPENAI_API_KEY": {"key": "codegate/production/model-gateway/openai", "property": "api-key"},
    }

    runtime_expected = {
        "codegate-runtime-secrets": (
            "codegate-runtime-system",
            "codegate-runtime-secret-store",
            {"RUNTIME_INTERNAL_TOKEN", "OPENVPN_ISSUER_TOKEN", "SANDBOX_RUNNER_INTERNAL_TOKEN", "ELASTICSEARCH_API_KEY"},
        ),
        "codegate-desktop-secrets": (
            "codegate-desktop-system",
            "codegate-desktop-secret-store",
            {"DESKTOP_GATEWAY_INTERNAL_TOKEN", "DESKTOP_SESSION_SIGNING_KEY"},
        ),
        "codegate-openvpn-secrets": (
            "codegate-vpn-system",
            "codegate-vpn-secret-store",
            {"DATABASE_URL", "OPENVPN_ISSUER_TOKEN", "OPENVPN_DOWNLOAD_INTERNAL_TOKEN", "OPENVPN_MASTER_KEY"},
        ),
        "codegate-openvpn-pki": (
            "codegate-vpn-system",
            "codegate-vpn-secret-store",
            {"ca.crt", "ca.key", "tls-crypt.key"},
        ),
    }
    runtime_docs = documents("infra/kubernetes/runtime-plane/base/application-external-secrets.yaml")
    assert {item["metadata"]["name"] for item in runtime_docs} == set(runtime_expected)
    for item in runtime_docs:
        name = item["metadata"]["name"]
        namespace, store, keys = runtime_expected[name]
        spec = item["spec"]
        assert item["metadata"]["namespace"] == namespace
        assert spec["secretStoreRef"] == {"kind": "SecretStore", "name": store}
        assert spec["target"]["name"] == name
        assert {entry["secretKey"] for entry in spec["data"]} == keys

    all_docs = platform_docs + runtime_docs
    token_sources: dict[str, set[str]] = {}
    for item in all_docs:
        for entry in item["spec"]["data"]:
            key = entry["secretKey"]
            if key.endswith("_INTERNAL_TOKEN") or key == "OPENVPN_ISSUER_TOKEN":
                token_sources.setdefault(key, set()).add(entry["remoteRef"]["key"])
    assert all(len(paths) == 1 for paths in token_sources.values())


def assert_registry_mount(relative: str, deployment_name: str, auth_secret: str, home: str) -> None:
    deployment = resource(relative, "Deployment", deployment_name)
    pod = deployment["spec"]["template"]["spec"]
    container = pod["containers"][0]
    volumes = {item["name"]: item for item in pod["volumes"]}
    mounts = {item["name"]: item for item in container["volumeMounts"]}
    env = {item["name"]: item for item in container["env"]}

    assert volumes["registry-auth"]["secret"]["secretName"] == auth_secret
    assert volumes["registry-ca"]["secret"]["secretName"] == "codegate-private-registry-ca"
    assert volumes["registry-ca"]["secret"]["items"] == [{"key": "ca.crt", "path": "ca.crt"}]
    assert mounts["registry-auth"] == {"name": "registry-auth", "mountPath": f"{home}/.docker", "readOnly": True}
    assert mounts["registry-ca"] == {"name": "registry-ca", "mountPath": "/etc/codegate/registry-ca", "readOnly": True}
    assert env["DOCKER_CONFIG"]["value"] == f"{home}/.docker"
    assert env["SSL_CERT_DIR"]["value"] == "/etc/ssl/certs"
    assert env["SSL_CERT_FILE"]["value"] == "/etc/codegate/registry-ca/ca.crt"
    assert env["COSIGN_REPOSITORY"]["valueFrom"]["configMapKeyRef"] == {
        "name": "codegate-platform-config",
        "key": "COSIGN_REPOSITORY",
    }


def assert_registry_egress() -> None:
    config = resource("infra/kubernetes/base/configmap.yaml", "ConfigMap", "codegate-platform-config")["data"]
    policy = resource(
        "infra/kubernetes/base/network-policies.yaml",
        "NetworkPolicy",
        "builder-and-validator-to-private-registry",
    )
    selector = policy["spec"]["podSelector"]["matchExpressions"]
    assert selector == [{
        "key": "app.kubernetes.io/name",
        "operator": "In",
        "values": ["codegate-builder", "codegate-validator"],
    }]
    rule = policy["spec"]["egress"][0]
    policy_cidrs = {peer["ipBlock"]["cidr"] for peer in rule["to"]}
    assert policy_cidrs == set(config["BUILD_EGRESS_CIDRS"].split(","))
    assert rule["ports"] == [{"protocol": "TCP", "port": 443}]
    assert config["BUILD_EGRESS_PORTS"] == "443"
    assert config["COSIGN_REPOSITORY"].startswith("registry.example.invalid/")


def assert_admission_contract() -> None:
    policy = resource(
        "infra/kubernetes/base/builder-workload-admission-policy.yaml",
        "ValidatingAdmissionPolicy",
        "codegate-builder-workload-shape",
    )
    expressions = "\n".join(item["expression"] for item in policy["spec"]["validations"])
    for required in (
        "codegate-private-registry-ca",
        "SSL_CERT_FILE",
        "/etc/codegate/registry-ca/ca.crt",
        "params.data['BUILDKIT_IMAGE']",
        "params.data['BUILD_EGRESS_CIDRS']",
        "object.data.size() == 3",
        "codegate-component-policy.json",
        "v.configMap.items.size() == 2",
        "request.namespace.startsWith('cg-build-')",
    ):
        assert required in expressions
    binding = resource(
        "infra/kubernetes/base/builder-workload-admission-policy.yaml",
        "ValidatingAdmissionPolicyBinding",
        "codegate-builder-workload-shape",
    )
    assert binding["spec"]["validationActions"] == ["Deny"]
    assert binding["spec"]["paramRef"] == {
        "name": "codegate-platform-config",
        "namespace": "codegate-platform",
        "parameterNotFoundAction": "Deny",
    }
    builder_boundary = resource(
        "infra/kubernetes/base/builder.yaml",
        "ValidatingAdmissionPolicy",
        "codegate-builder-namespace-boundary",
    )
    builder_boundary_expression = builder_boundary["spec"]["validations"][0]["expression"]
    assert "oldObject.metadata.name.startsWith('cg-build-')" in builder_boundary_expression
    assert "oldObject.metadata.labels['app.kubernetes.io/name'] == 'codegate-builder'" in builder_boundary_expression

    runtime_policy = resource(
        "infra/kubernetes/runtime-plane/base/workload-admission-policy.yaml",
        "ValidatingAdmissionPolicy",
        "codegate-runtime-workload-shape",
    )
    runtime_expressions = "\n".join(item["expression"] for item in runtime_policy["spec"]["validations"])
    assert "request.namespace.startsWith('range-')" in runtime_expressions
    assert "request.namespace.startsWith('validation-')" in runtime_expressions
    for required in (
        "object.metadata.name != 'default-deny'",
        "object.metadata.name != 'allow-vpn-public'",
        "object.metadata.name != 'allow-desktop-gateway'",
        "object.metadata.name != 'allow-vpn-bootstrap'",
        "p.port == 53",
        "'codegate-desktop-system'",
        "'codegate-vpn-system'",
    ):
        assert required in runtime_expressions
    delete_policy = resource(
        "infra/kubernetes/runtime-plane/base/admission-policy.yaml",
        "ValidatingAdmissionPolicy",
        "codegate-runtime-namespace-boundary",
    )
    delete_rules = delete_policy["spec"]["matchConstraints"]["resourceRules"]
    assert any("DELETE" in rule["operations"] and "namespaces" in rule["resources"] for rule in delete_rules)
    delete_expression = delete_policy["spec"]["validations"][0]["expression"]
    assert "oldObject.metadata.name.startsWith('range-')" in delete_expression
    assert "oldObject.metadata.name.startsWith('validation-')" in delete_expression
    assert "oldObject.metadata.labels['app.kubernetes.io/managed-by'] == 'codegate-runtime'" in delete_expression


def assert_ai_egress_contract() -> None:
    config = resource("infra/kubernetes/base/configmap.yaml", "ConfigMap", "codegate-platform-config")["data"]
    expected_provider_paths = {
        "GENERATION_PROVIDER_URL": "/v1/generate",
        "REVIEW_PROVIDER_URL": "/v1/review",
        "RUBRIC_PROVIDER_URL": "/v1/rubric",
    }
    for key, path in expected_provider_paths.items():
        parsed = urlparse(config[key])
        assert (parsed.scheme, parsed.hostname, parsed.port, parsed.path) == ("http", "model-gateway", 9010, path)

    policy = resource(
        "infra/kubernetes/base/ai-egress-policy.yaml",
        "CiliumNetworkPolicy",
        "ai-approved-external-egress",
    )
    assert policy["spec"]["endpointSelector"]["matchLabels"] == {
        "app.kubernetes.io/name": "codegate-ai",
    }
    fqdn_rule = next(rule for rule in policy["spec"]["egress"] if "toFQDNs" in rule)
    allowed_hosts = {entry["matchName"] for entry in fqdn_rule["toFQDNs"]}
    assert allowed_hosts == {"services.nvd.nist.gov"}
    assert fqdn_rule["toPorts"] == [{"ports": [{"port": "443", "protocol": "TCP"}]}]
    dns_rule = next(rule for rule in policy["spec"]["egress"] if "toEndpoints" in rule)
    assert dns_rule["toPorts"][0]["rules"]["dns"] == [{"matchPattern": "*"}]

    gateway_network_docs = documents("infra/kubernetes/base/model-gateway-network-policy.yaml")
    ai_to_gateway = next(item for item in gateway_network_docs if item.get("metadata", {}).get("name") == "ai-to-model-gateway")
    ai_rule = ai_to_gateway["spec"]["egress"][0]
    assert ai_rule["to"] == [{"podSelector": {"matchLabels": {"app.kubernetes.io/name": "model-gateway"}}}]
    assert ai_rule["ports"] == [{"protocol": "TCP", "port": 9010}]

    gateway_egress = next(item for item in gateway_network_docs if item.get("kind") == "CiliumNetworkPolicy")
    gateway_fqdn_rule = next(rule for rule in gateway_egress["spec"]["egress"] if "toFQDNs" in rule)
    assert gateway_fqdn_rule["toFQDNs"] == [{"matchName": "api.openai.com"}]
    assert gateway_fqdn_rule["toPorts"] == [{"ports": [{"port": "443", "protocol": "TCP"}]}]
    openai_url = urlparse(config["OPENAI_BASE_URL"])
    assert (openai_url.scheme, openai_url.hostname, openai_url.path) == ("https", "api.openai.com", "/v1")

    gateway = resource("infra/kubernetes/base/model-gateway.yaml", "Deployment", "model-gateway")
    pod = gateway["spec"]["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False
    container = pod["containers"][0]
    secret_refs = {
        item["name"]: item["valueFrom"]["secretKeyRef"]
        for item in container["env"]
        if "valueFrom" in item
    }
    assert secret_refs == {
        "MODEL_GATEWAY_INTERNAL_TOKEN": {"name": "codegate-model-gateway-secrets", "key": "MODEL_GATEWAY_INTERNAL_TOKEN"},
        "OPENAI_API_KEY": {"name": "codegate-model-gateway-secrets", "key": "OPENAI_API_KEY"},
    }
    assert container["securityContext"]["readOnlyRootFilesystem"] is True


def assert_node_registry_contract() -> None:
    tasks = yaml_value("infra/server/roles/rke2_common/tasks/main.yml")
    assert isinstance(tasks, list)
    for task_name in (
        "Install the private registry TLS CA",
        "Install the protected RKE2 private registry configuration",
    ):
        task = named(tasks, task_name)
        assert task["no_log"] is True
        module = task.get("ansible.builtin.template")
        assert module and module["owner"] == "root" and module["group"] == "root" and module["mode"] == "0600"
        assert task["notify"] == "Restart RKE2 node"

    registry_template = (ROOT / "infra/server/roles/rke2_common/templates/registries.yaml.j2").read_text(encoding="utf-8")
    assert "private_registry_pull_username" in registry_template
    assert "private_registry_pull_password" in registry_template
    assert "private_registry_ca_path" in registry_template
    assert "insecure_skip_verify" not in registry_template

    handlers = yaml_value("infra/server/roles/rke2_common/handlers/main.yml")
    assert isinstance(handlers, list)
    assert {item["ansible.builtin.service"]["name"] for item in handlers} == {"rke2-server", "rke2-agent"}
    assert all(item["listen"] == "Restart RKE2 node" for item in handlers)

    preflight = yaml_value("infra/server/roles/preflight/tasks/main.yml")
    secret_validation = named(preflight, "Reject placeholder or malformed secrets")
    assertions = "\n".join(secret_validation["ansible.builtin.assert"]["that"])
    assert "private_registry_ca_pem is not search('PRIVATE KEY')" in assertions
    assert secret_validation["no_log"] is True

    node_validation = yaml_value("infra/server/roles/validation_node/tasks/main.yml")
    registry_probe = named(node_validation, "Verify the private registry credential and CA trust")
    uri = registry_probe["ansible.builtin.uri"]
    assert uri["url"] == "{{ private_registry_endpoint }}/v2/"
    assert uri["ca_path"] == "{{ private_registry_ca_path }}"
    assert uri["validate_certs"] is True and uri["status_code"] == 200
    assert registry_probe["no_log"] is True


def assert_release_and_edge_contract() -> None:
    variables = yaml_value("infra/server/group_vars/all.yml")
    assert variables["rke2_version"] == "v1.36.2+rke2r1"
    assert variables["longhorn_chart_version"] == "1.12.0"
    assert variables["cert_manager_chart_version"] == "v1.21.0"
    assert variables["rke2_ingress_controller"] == "traefik"
    assert variables["install_ingress_nginx"] is False

    server_config = (ROOT / "infra/server/roles/rke2_server/templates/config-server.yaml.j2").read_text(encoding="utf-8")
    assert "ingress-controller: {{ rke2_ingress_controller | to_json }}" in server_config
    assert "rke2-traefik" not in "\n".join(
        line.strip() for line in server_config.splitlines() if line.strip().startswith("-")
    )

    traefik = (ROOT / "infra/server/roles/rke2_server/templates/rke2-traefik-config.yaml.j2").read_text(encoding="utf-8")
    for required in (
        "name: rke2-traefik",
        "kind: DaemonSet",
        "name: traefik",
        "hostPort: null",
        "type: NodePort",
        "externalTrafficPolicy: Local",
        "sendAnonymousUsage: false",
        "enabled: false",
    ):
        assert required in traefik
    assert "insecure: true" not in traefik

    haproxy = (ROOT / "infra/server/roles/ha_endpoint/templates/haproxy.cfg.j2").read_text(encoding="utf-8")
    assert haproxy.count("send-proxy-v2") == 2

    for relative in (
        "infra/kubernetes/base/ingress.yaml",
        "infra/kubernetes/runtime-plane/base/desktop-gateway.yaml",
        "infra/kubernetes/runtime-plane/base/openvpn.yaml",
    ):
        ingress_docs = [item for item in documents(relative) if item.get("kind") == "Ingress"]
        assert ingress_docs and all(item["spec"]["ingressClassName"] == "traefik" for item in ingress_docs)
        assert all(not any(key.startswith("nginx.ingress.kubernetes.io/") for key in item.get("metadata", {}).get("annotations", {})) for item in ingress_docs)


def assert_longhorn_backup_contract() -> None:
    variables = yaml_value("infra/server/group_vars/all.yml")
    assert variables["longhorn_backup_schedule"] == "0 */6 * * *"
    assert variables["longhorn_backup_retention"] >= 28
    assert 1 <= variables["longhorn_backup_concurrency"] <= 4

    addons = (ROOT / "infra/server/roles/platform_addons/templates/platform-addons.yaml.j2").read_text(encoding="utf-8")
    assert "jobList: '[{\"name\":\"codegate-volume-backup\",\"isGroup\":false}]'" in addons
    assert 'allowRecurringJobWhileVolumeDetached: "true"' in addons

    recurring = (ROOT / "infra/server/roles/platform_addons/templates/longhorn-recurring-backup.yaml.j2").read_text(encoding="utf-8")
    for required in (
        "apiVersion: longhorn.io/v1beta2",
        "name: codegate-volume-backup",
        "cron: {{ longhorn_backup_schedule | to_json }}",
        "task: backup",
        "retain: {{ longhorn_backup_retention }}",
        "concurrency: {{ longhorn_backup_concurrency }}",
    ):
        assert required in recurring

    addon_tasks = yaml_value("infra/server/roles/platform_addons/tasks/main.yml")
    named(addon_tasks, "Install the recurring off-node Longhorn volume backup")
    wait = named(addon_tasks, "Wait for the recurring Longhorn backup contract")
    assert wait["retries"] == 30 and wait["until"] == "longhorn_recurring_backup.rc == 0"

    cluster_validation = yaml_value("infra/server/roles/validation_cluster/tasks/main.yml")
    named(cluster_validation, "Read the recurring Longhorn volume backup contract")
    invariants = named(cluster_validation, "Assert cluster production invariants")["ansible.builtin.assert"]["that"]
    invariant_text = "\n".join(str(item) for item in invariants)
    assert "recurringJobSelector" in invariant_text
    assert "validated_longhorn_backup" in invariant_text


def main() -> None:
    assert_application_external_secrets()
    assert_registry_external_secrets()
    assert_registry_mount("infra/kubernetes/base/builder.yaml", "codegate-builder", "codegate-build-registry", "/home/builder")
    assert_registry_mount("infra/kubernetes/base/validator.yaml", "codegate-validator", "codegate-validator-registry", "/home/validator")
    assert_registry_egress()
    assert_admission_contract()
    assert_ai_egress_contract()
    assert_node_registry_contract()
    assert_release_and_edge_contract()
    assert_longhorn_backup_contract()
    print("Infrastructure contracts validated")


if __name__ == "__main__":
    main()
