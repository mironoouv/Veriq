"""Verify the running production-oriented stack without printing its configuration."""

import json
import os
import subprocess
from typing import Any

COMPOSE = ["docker", "compose", "-f", "compose.yaml", "-f", "compose.prod.yaml"]
SERVICES = {"postgres", "redis", "migrate", "api", "worker", "web"}
NETWORKS = {
    "postgres": {"database"},
    "redis": {"queue"},
    "migrate": {"database"},
    "api": {"app", "database", "queue"},
    "worker": {"database", "queue"},
    "web": {"app", "edge"},
}
SECRETS = (
    "VERIQ_DB_PASSWORD",
    "VERIQ_API_DB_PASSWORD",
    "VERIQ_WORKER_DB_PASSWORD",
)
DB_ROLE_CHECK = """
import sys
from sqlalchemy import text
from veriq.database import create_database_engine

with create_database_engine().connect() as connection:
    role, restricted = connection.execute(text(
        "SELECT current_user, NOT (rolsuper OR rolbypassrls) "
        "FROM pg_roles WHERE rolname = current_user"
    )).one()
    assert role == sys.argv[1] and restricted
"""


def output(*args: str) -> str:
    return subprocess.check_output(args, encoding="utf-8", timeout=30).strip()


def validate_container(container: dict[str, Any]) -> str:
    service = container["Config"]["Labels"]["com.docker.compose.service"]
    assert isinstance(service, str)
    host = container["HostConfig"]
    assert host["ReadonlyRootfs"], service
    assert not host["Privileged"], service
    assert "ALL" in host["CapDrop"], service
    assert any(
        option.startswith("no-new-privileges") for option in host["SecurityOpt"]
    ), service
    assert not any(
        mount["Destination"] == "/var/run/docker.sock" for mount in container["Mounts"]
    )
    assert host["RestartPolicy"]["Name"] == (
        "no" if service == "migrate" else "unless-stopped"
    )
    if service == "migrate":
        assert container["State"]["Status"] == "exited"
        assert container["State"]["ExitCode"] == 0
        assert container["Config"]["User"] == "10001:10001"
    else:
        assert container["State"]["Health"]["Status"] == "healthy", service
        assert int(output(*COMPOSE, "exec", "-T", service, "id", "-u")) > 0, service

    bindings = host["PortBindings"]
    if service == "web":
        assert set(bindings) == {"8080/tcp"}
        assert bindings["8080/tcp"] == [
            {
                "HostIp": "127.0.0.1",
                "HostPort": os.environ.get("VERIQ_PROD_WEB_PORT", "8080"),
            }
        ]
    else:
        assert not bindings, service
    return service


def main() -> None:
    if os.environ.get("COMPOSE_PROJECT_NAME") not in {
        "veriq-prod-ci",
        "veriq-prod-smoke",
    }:
        raise SystemExit("Use the dedicated production smoke project")
    secrets = tuple(os.environ[name] for name in SECRETS)
    assert all(secrets) and len(set(secrets)) == 3
    config = json.loads(output(*COMPOSE, "config", "--format", "json"))
    for name in ("database", "queue", "app"):
        assert config["networks"][name]["internal"]
    assert set(config["services"]) == SERVICES
    for service, networks in NETWORKS.items():
        assert set(config["services"][service]["networks"]) == networks, service

    ids = output(*COMPOSE, "ps", "-aq").splitlines()
    containers = json.loads(output("docker", "inspect", *ids))
    assert {validate_container(container) for container in containers} == SERVICES
    for container in containers:
        service = container["Config"]["Labels"]["com.docker.compose.service"]
        environment = dict(item.split("=", 1) for item in container["Config"]["Env"])
        if service in {"api", "worker"}:
            index = 1 if service == "api" else 2
            assert environment.get("VERIQ_DB_PASSWORD") == secrets[index]
            assert all(
                value not in environment.values()
                for i, value in enumerate(secrets)
                if i != index
            )
        if service in {"web", "redis"}:
            assert all(value not in environment.values() for value in secrets)

    for service, role in (("api", "veriq_api"), ("worker", "veriq_worker")):
        output(*COMPOSE, "exec", "-T", service, "python", "-c", DB_ROLE_CHECK, role)
    output(
        *COMPOSE,
        "exec",
        "-T",
        "web",
        "sh",
        "-ec",
        "! command -v node && ! command -v npm",
    )
    for image in {container["Image"] for container in containers}:
        artifact = output("docker", "image", "inspect", image)
        history = output(
            "docker",
            "image",
            "history",
            "--no-trunc",
            "--format",
            "{{.CreatedBy}}",
            image,
        )
        assert not any(value in artifact or value in history for value in secrets), (
            "Secret in image metadata"
        )
    logs = output(*COMPOSE, "logs", "--no-color")
    assert not any(value in logs for value in secrets), "Secret in Compose logs"
    print(
        "Production Compose: health, non-root users, runtime DB roles, network exposure and secret checks passed."
    )


if __name__ == "__main__":
    main()
