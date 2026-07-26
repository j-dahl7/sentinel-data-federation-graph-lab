#!/usr/bin/env python3
"""Validate synthetic federation fixtures and reusable query contracts."""

from __future__ import annotations

import csv
import json
from pathlib import Path
import re
import sys
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
QUERIES = ROOT / "queries"
RESOURCE_SCHEMA = (
    "resourceId",
    "resourceName",
    "resourceType",
    "criticality",
    "detectionHint",
)
ACCESS_SCHEMA = (
    "principalId",
    "principalDisplayName",
    "resourceId",
    "accessRole",
    "accessSource",
    "riskLabel",
)
GUID = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}(?![0-9a-f])")


class ValidationError(ValueError):
    pass


def load_csv(name: str, schema: tuple[str, ...]) -> list[dict[str, str]]:
    path = FIXTURES / f"{name}.csv"
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != schema:
            raise ValidationError(f"{path.name} schema must be {', '.join(schema)}")
        rows = list(reader)
    validate_rows(path.name, rows, schema)
    return rows


def load_json(name: str, schema: tuple[str, ...]) -> list[dict[str, str]]:
    path = FIXTURES / f"{name}.json"
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValidationError(f"{path.name} is not valid JSON") from error
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ValidationError(f"{path.name} must be an array of objects")
    validate_rows(path.name, rows, schema)
    return rows


def validate_rows(name: str, rows: list[dict[str, str]], schema: tuple[str, ...]) -> None:
    if not rows:
        raise ValidationError(f"{name} must not be empty")
    for index, row in enumerate(rows, 1):
        if tuple(row.keys()) != schema:
            raise ValidationError(f"{name} row {index} keys do not match the schema")
        for key, value in row.items():
            if not isinstance(value, str) or not value.strip():
                raise ValidationError(f"{name} row {index} field {key} must be a non-empty string")


def normalized(rows: Iterable[dict[str, str]], schema: tuple[str, ...]) -> list[tuple[str, ...]]:
    return sorted(tuple(row[column] for column in schema) for row in rows)


def validate_safe_values(rows: Iterable[dict[str, str]]) -> None:
    for row in rows:
        for key, value in row.items():
            lower = value.lower()
            if GUID.search(value) or "/subscriptions/" in lower:
                raise ValidationError(f"{key} contains a tenant/subscription-shaped identifier")
            if any(marker in lower for marker in ("clientsecret", "bearer ", "sharedaccesssignature=")):
                raise ValidationError(f"{key} contains credential-shaped material")
        if "resourceId" in row and not row["resourceId"].startswith("urn:nls:synthetic:resource:"):
            raise ValidationError("resourceId must use the synthetic resource URN namespace")
        if "principalId" in row and not row["principalId"].startswith("urn:nls:synthetic:principal:"):
            raise ValidationError("principalId must use the synthetic principal URN namespace")


def load_and_validate() -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    resources_csv = load_csv("ResourceCriticality", RESOURCE_SCHEMA)
    resources_json = load_json("ResourceCriticality", RESOURCE_SCHEMA)
    access_csv = load_csv("PrincipalResourceAccess", ACCESS_SCHEMA)
    access_json = load_json("PrincipalResourceAccess", ACCESS_SCHEMA)

    if normalized(resources_csv, RESOURCE_SCHEMA) != normalized(resources_json, RESOURCE_SCHEMA):
        raise ValidationError("ResourceCriticality CSV and JSON rows differ")
    if normalized(access_csv, ACCESS_SCHEMA) != normalized(access_json, ACCESS_SCHEMA):
        raise ValidationError("PrincipalResourceAccess CSV and JSON rows differ")

    if len(resources_csv) != 2 or len(access_csv) != 4:
        raise ValidationError("the companion contract requires two resources and four access paths")

    resource_ids = [row["resourceId"] for row in resources_csv]
    if len(resource_ids) != len(set(resource_ids)):
        raise ValidationError("resourceId values must be unique")
    if any(row["resourceId"] not in set(resource_ids) for row in access_csv):
        raise ValidationError("every access path must reference a known resource")

    identities: dict[str, tuple[str, str]] = {}
    for row in access_csv:
        identity = (row["principalDisplayName"], row["riskLabel"])
        if row["principalId"] in identities and identities[row["principalId"]] != identity:
            raise ValidationError("a principalId maps to inconsistent identity metadata")
        identities[row["principalId"]] = identity

    expected_paths = {
        ("shadow-sync-prod-sp", "Key Vault Secrets Officer", "UnknownDirectGrant", "simulated-bad-actor"),
        ("shadow-sync-prod-sp", "Storage Blob Data Owner", "UnknownDirectGrant", "simulated-bad-actor"),
        ("sentinel-data-federation-lab-sp", "Key Vault Secrets User", "InheritedPath", "expected"),
        ("sentinel-data-federation-lab-sp", "Storage Blob Data Reader", "RoleAssignment", "expected"),
    }
    actual_paths = {
        (row["principalDisplayName"], row["accessRole"], row["accessSource"], row["riskLabel"])
        for row in access_csv
    }
    if actual_paths != expected_paths:
        raise ValidationError("access paths do not match the companion-blog synthetic contract")

    validate_safe_values([*resources_csv, *access_csv])
    return resources_csv, access_csv


def joined_paths() -> list[dict[str, str]]:
    resources, access = load_and_validate()
    resources_by_id = {row["resourceId"]: row for row in resources}
    return [{**edge, **resources_by_id[edge["resourceId"]]} for edge in access]


def validate_queries() -> None:
    kql_files = sorted(QUERIES.glob("*.kql"))
    if len(kql_files) != 3:
        raise ValidationError("exactly three reusable KQL queries are required")
    for query in kql_files:
        text = query.read_text(encoding="utf-8")
        if "ResourceCriticality_federationlab" not in text or "PrincipalResourceAccess_federationlab" not in text:
            raise ValidationError(f"{query.name} must bind both suffixed federation tables")
        if GUID.search(text) or "/subscriptions/" in text.lower():
            raise ValidationError(f"{query.name} contains a live-looking identifier")

    graph_query = (QUERIES / "simulated-bad-actor-paths.gql").read_text(encoding="utf-8")
    required = ("EntraServicePrincipal", "CAN_ACCESS", "AzureResource", "simulated-bad-actor", "LIMIT 50")
    if not all(fragment in graph_query for fragment in required):
        raise ValidationError("GQL query does not match the documented bounded graph schema")
    if GUID.search(graph_query) or "/subscriptions/" in graph_query.lower():
        raise ValidationError("GQL query contains a live-looking identifier")


def main() -> int:
    try:
        resources, access = load_and_validate()
        validate_queries()
    except (OSError, ValidationError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"PASS: validated {len(resources)} resources, {len(access)} access paths, and 4 reusable queries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
