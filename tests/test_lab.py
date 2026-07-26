from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts" / "validate_fixtures.py"
spec = importlib.util.spec_from_file_location("validate_fixtures", VALIDATOR_PATH)
assert spec and spec.loader
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class FederationLabContractTests(unittest.TestCase):
    def test_validator_cli_passes(self) -> None:
        result = subprocess.run(
            [sys.executable, str(VALIDATOR_PATH)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_join_has_all_four_documented_paths(self) -> None:
        rows = validator.joined_paths()
        self.assertEqual(len(rows), 4)
        self.assertEqual(sum(row["riskLabel"] == "simulated-bad-actor" for row in rows), 2)
        self.assertEqual(sum(row["riskLabel"] == "expected" for row in rows), 2)

    def test_fixture_identifiers_are_explicitly_synthetic(self) -> None:
        resources, access = validator.load_and_validate()
        for row in resources:
            self.assertTrue(row["resourceId"].startswith("urn:nls:synthetic:resource:"))
        for row in access:
            self.assertTrue(row["principalId"].startswith("urn:nls:synthetic:principal:"))

    def test_executable_artifacts_have_no_live_shaped_identifiers(self) -> None:
        guid = re.compile(r"(?i)[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
        for directory in (ROOT / "fixtures", ROOT / "queries"):
            for path in directory.iterdir():
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(guid.search(text), path)
                self.assertNotIn("/subscriptions/", text.lower(), path)

    def test_queries_keep_bounded_alias_and_graph_contracts(self) -> None:
        validator.validate_queries()

    def test_queries_match_the_companion_article_contract(self) -> None:
        expected = {
            "principal-paths.kql": '''
let ResourceCriticality = ResourceCriticality_federationlab;
let PrincipalResourceAccess = PrincipalResourceAccess_federationlab;
PrincipalResourceAccess
| where principalDisplayName == "shadow-sync-prod-sp"
| join kind=inner ResourceCriticality on resourceId
| project principalDisplayName, resourceName, criticality, accessRole, accessSource, detectionHint, riskLabel
''',
            "high-value-exposure.kql": '''
let ResourceCriticality = ResourceCriticality_federationlab;
let PrincipalResourceAccess = PrincipalResourceAccess_federationlab;
PrincipalResourceAccess
| join kind=inner ResourceCriticality on resourceId
| where criticality in ("crown-jewel", "high")
| summarize AccessRoles = make_set(accessRole), ResourceCount = dcount(resourceName) by principalDisplayName, riskLabel
| sort by ResourceCount desc
''',
            "workbook-summary.kql": '''
let ResourceCriticality = ResourceCriticality_federationlab;
let PrincipalResourceAccess = PrincipalResourceAccess_federationlab;
PrincipalResourceAccess
| join kind=inner ResourceCriticality on resourceId
| where criticality in ("crown-jewel", "high")
| project principalDisplayName, resourceName, criticality, accessRole, accessSource, riskLabel
| sort by riskLabel asc, criticality asc
''',
            "simulated-bad-actor-paths.gql": '''
MATCH (sp:EntraServicePrincipal)-[rel_access:CAN_ACCESS]->(r:AzureResource)
WHERE sp.riskLabel = 'simulated-bad-actor'
RETURN sp, r, rel_access
LIMIT 50
''',
        }
        for name, content in expected.items():
            self.assertEqual((ROOT / "queries" / name).read_text(encoding="utf-8").strip(), content.strip())


if __name__ == "__main__":
    unittest.main()
