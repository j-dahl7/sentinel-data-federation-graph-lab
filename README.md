# Sentinel Data Federation and Custom Graphs Lab

This is the safe companion lab for [Investigate Hidden Privilege Paths with
Microsoft Sentinel Data Federation and Custom
Graphs](https://nineliveszerotrust.com/blog/sentinel-data-federation-custom-graphs/).
It provides synthetic source data and reusable queries for the article's
service-principal-to-resource attack path.

> **Guide, not deployment automation:** This repository creates no tenant
> object, connector, identity, graph, notebook, schedule, or cloud resource.
> Every checked-in record is synthetic. You must review the current preview
> documentation, roles, cost model, and regional availability before adapting
> the guide in a disposable environment.

## What is included

```text
fixtures/
  ResourceCriticality.csv         Two synthetic resource classifications
  ResourceCriticality.json        JSON equivalent
  PrincipalResourceAccess.csv     Four synthetic principal-to-resource edges
  PrincipalResourceAccess.json    JSON equivalent
queries/
  principal-paths.kql              The article's suspicious-principal join
  high-value-exposure.kql          Broader high-value exposure summary
  workbook-summary.kql             Review-friendly tabular projection
  simulated-bad-actor-paths.gql    Custom-graph traversal
scripts/validate_fixtures.py       Schema, safety, and query validator
tests/test_lab.py                  Offline contract tests
```

The two fixture formats contain the same rows. CSV is convenient for ingestion
preparation; JSON is convenient for review and transformation. Neither is
intended to be pointed at a production connector unchanged.

## Safety and preview limits

- Use a disposable Sentinel workspace and synthetic copies of these fixtures.
- Do not add real tenant, subscription, object, client, or resource IDs to this
  repository. Synthetic IDs use the `urn:nls:synthetic:` namespace.
- Never commit client secrets, tokens, connection strings, notebook output, or
  exported tenant data. `.gitignore` blocks common local forms, but it is not a
  credential scanner.
- Data federation support, connector names, permissions, graph limits, and
  pricing are preview behavior and can change. Confirm them before every run.
- The article's validated public-source path uses ADLS, Databricks, or Fabric.
  Private-endpoint-only storage was outside that path; do not assume it works.
- For an ADLS source, prepare Delta or Parquet data. Use a same-tenant,
  read-only service principal; place any short-lived secret in Key Vault, never
  in a query, notebook, fixture, or repository variable.
- Use least privilege. At validation time, the managed identity needed Key
  Vault Secrets User on the selected vault, while the operator needed the
  Sentinel Data permissions required to manage the preview resources. Recheck
  Microsoft's current role requirements rather than copying historical grants.
- Custom graphs are ephemeral investigation artifacts. This guide does not
  promise a supported production graph model, automatic refresh, or workbook
  deployment.

The companion investigation recorded these preview constraints. Treat them as
a preflight checklist to revalidate, not as permanent product guarantees:

| Constraint | Companion-lab boundary |
|---|---|
| Workspace | Must already be onboarded to the Sentinel data lake |
| Source networking | Federated source must be publicly reachable; private endpoints were unsupported |
| Key Vault networking | Public access from all networks was required during connector setup; restrict it again immediately after creation if current behavior permits |
| Federation behavior | Read-only; the Sentinel query path cannot write back to the source |
| Visibility delay | Up to 15 minutes for new federated rows in KQL and up to 24 hours in notebooks |
| Encryption | Customer-managed-key workspaces could not use the data-lake federation/graph experience |
| Scale | Maximum 100 federation connector instances per tenant |
| Authoring | Custom-graph authoring used Jupyter through the Microsoft Sentinel VS Code extension |
| Cost | Federation avoided Sentinel ingestion/storage charges, but queries used data-lake/advanced-insights meters; graph operations used the graph meter; source-platform charges remained separate |

## 1. Validate the local artifacts

Python 3.9 or newer is the only offline prerequisite:

```bash
python3 scripts/validate_fixtures.py
python3 -m unittest discover -s tests -v
```

Validation proves that CSV and JSON agree, schemas are exact, all access edges
reference a known resource, the four companion-blog paths are present, and no
GUID- or subscription-shaped identifier appears in an executable artifact.

## 2. Prepare a disposable federated source

1. Copy the two CSV datasets into an access-restricted lab staging area.
2. Convert them to supported Delta or Parquet tables named
   `ResourceCriticality` and `PrincipalResourceAccess`.
3. Keep the columns and string values unchanged for the first validation run.
4. Grant the source identity read-only access to only those lab paths.
5. Record a cleanup time and owner before creating a federation connector.

The schemas are:

| Table | Columns |
|---|---|
| `ResourceCriticality` | `resourceId`, `resourceName`, `resourceType`, `criticality`, `detectionHint` |
| `PrincipalResourceAccess` | `principalId`, `principalDisplayName`, `resourceId`, `accessRole`, `accessSource`, `riskLabel` |

The suspicious synthetic principal has two high-privilege direct grants. The
expected lab principal has read-only or secret-read access through ordinary
assignment paths. The contrast is intentional and contains no real identity.

## 3. Create bounded federation aliases

In your disposable environment, create the two federated table aliases with an
explicit `_federationlab` suffix:

- `ResourceCriticality_federationlab`
- `PrincipalResourceAccess_federationlab`

The checked-in KQL starts with `let` bindings for those exact names. If the
preview generates different table names, change only the right-hand sides of
the bindings in your private working copy. Keep the logical aliases on the
left so the rest of the query remains reusable.

Do not broaden the connector to a production container or lakehouse. Confirm
that the source identity can read the two intended lab tables and nothing else.

## 4. Run the KQL validations

Run `queries/principal-paths.kql` first. It should return exactly two rows for
`shadow-sync-prod-sp`, one for each synthetic resource.

Then run `queries/high-value-exposure.kql`. It should summarize:

| Principal | Expected resource count | Risk label |
|---|---:|---|
| `shadow-sync-prod-sp` | 2 | `simulated-bad-actor` |
| `sentinel-data-federation-lab-sp` | 2 | `expected` |

`queries/workbook-summary.kql` is a sorted, projection-only version suitable
for a temporary review table. This repository does not deploy a workbook.

## 5. Build an ephemeral custom graph

Use only the four joined synthetic rows to create:

- `EntraServicePrincipal` nodes keyed by `principalId`;
- `AzureResource` nodes keyed by `resourceId`; and
- `CAN_ACCESS` relationships with `accessRole` and `accessSource` properties.

Apply `riskLabel` to the service-principal nodes and `criticality` plus
`detectionHint` to resource nodes. Run
`queries/simulated-bad-actor-paths.gql`; it selects only paths beginning at the
synthetic `simulated-bad-actor` principal and caps the result at 50.

If you create a scheduled transformation job for the preview, use the smallest
practical interval, a named lab owner, and a same-day expiration. Do not infer
that the graph continuously tracks source changes unless you directly verify
that behavior in the current preview.

## Expected result and claim boundary

The lab proves a reproducible query and graph shape over synthetic data. It
does not prove production connector support, private endpoint support, live
identity risk, automatic graph refresh, or detection efficacy. A rendered edge
is evidence only for the synthetic fixture that produced it.

## Cleanup

Cleanup is part of the exercise. In this order:

1. stop and delete any scheduled graph/transformation job;
2. delete the custom graph and confirm it no longer returns nodes or edges;
3. remove both `_federationlab` aliases/connectors;
4. remove the two staged Delta/Parquet tables and any generated notebook output;
5. revoke the source identity's lab-path and Key Vault role assignments;
6. delete its short-lived secret and the disposable identity if it has no other
   approved owner; and
7. review cost and activity logs for unexpected residual jobs or reads.

Do not use broad resource-group deletion as a substitute for identifying the
objects this lab created. Preserve only redacted screenshots or query counts
needed for evidence; do not preserve exported rows from a real tenant.

## License

MIT. Use the synthetic fixtures and queries for demos and education.
