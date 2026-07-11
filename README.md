# Microsoft Sentinel Data Federation and Custom Graph Lab

Companion assets for [Investigate Hidden Privilege Paths with Microsoft Sentinel Data Federation and Custom Graphs](https://nineliveszerotrust.com/blog/sentinel-data-federation-custom-graphs/).

This lab demonstrates how to keep entitlement and resource-criticality context in ADLS Gen2, federate the tables into the Microsoft Sentinel data lake, join them with KQL, and investigate a synthetic service principal's access with a custom graph.

## Verification status

**Last reviewed: 2026-07-10 — documentation and query assets verified; live deployment required.** The repository previously contained only this README. It now includes the four synthetic rows described by the article and reusable KQL/GQL files. CSV structure and query/table-name consistency were checked locally. No connector, Key Vault, Sentinel tenant, Spark session, or custom graph was created during this review, and these preview features can change.

## Repository contents

```text
queries/
  high-value-exposure.kql       # All principals reaching high-value resources
  rogue-principal-access.kql    # Focused investigation of the synthetic rogue SP
  rogue-principal-path.gql      # One-hop custom-graph traversal
sample-data/
  principal-resource-access.csv # Four synthetic access paths
  resource-criticality.csv      # Two synthetic high-value resources
```

The CSV files are source fixtures, not secrets and not directly deployable federation tables. Convert them into tables supported by your ADLS/Fabric/Databricks environment (the demonstrated environment used Delta-format tables) before configuring federation.

## Prerequisites and permissions

- A Microsoft Sentinel workspace onboarded to the Sentinel data lake.
- Access to the Microsoft Defender portal and the Microsoft Sentinel VS Code extension for notebook/graph authoring.
- A publicly reachable supported source: ADLS Gen2, Azure Databricks, or Microsoft Fabric. Private endpoints are not currently supported for federation.
- For ADLS Gen2: hierarchical namespace enabled; a same-tenant service principal with **Storage Blob Data Reader** on the source; its client secret stored in Key Vault.
- The Sentinel platform identity whose name begins `msg-resources-` assigned **Key Vault Secrets User** on that vault.
- Microsoft Sentinel **Data (manage)** permission over System tables to configure the connector, plus the graph/notebook permissions required by your tenant.

Use a dedicated, least-privileged service principal and a short-lived client secret. Never put a tenant ID, client secret, storage key, or production resource identifier into these sample files.

## Prepare the two source tables

1. Review the obviously synthetic IDs and values under `sample-data/`.
2. Replace the placeholder resource IDs only if you are using disposable lab resources. Do not upload real employee, entitlement, or production inventory data for this exercise.
3. In a Spark-capable environment, read each CSV with headers, apply explicit string schemas, and write two external tables named:
   - `ResourceCriticality`
   - `PrincipalResourceAccess`
4. Confirm the service principal can read the tables but cannot write or delete them.

Required columns:

| Table | Columns |
|---|---|
| `ResourceCriticality` | `resourceId`, `resourceName`, `resourceType`, `criticality`, `detectionHint` |
| `PrincipalResourceAccess` | `principalId`, `principalDisplayName`, `principalType`, `resourceId`, `accessRole`, `accessSource`, `riskLabel` |

## Configure ADLS Gen2 federation

1. In Microsoft Defender, open **Microsoft Sentinel > Configuration > Data connectors**.
2. Under **Data federation**, select **Catalog > Azure Data Lake Storage > Connect a connector**.
3. Use an instance name such as `federationlab`. The instance name becomes the suffix of each federated table.
4. Provide the application/client ID, Key Vault URI, secret name, and public ADLS Gen2 URL.
5. Select the `ResourceCriticality` and `PrincipalResourceAccess` tables and connect.
6. Under **Configuration > Tables**, filter to **Federated**, refresh each schema, and verify the final names. With the example instance, they are `ResourceCriticality_federationlab` and `PrincipalResourceAccess_federationlab`.

If you choose another instance name, replace `_federationlab` in both KQL files before running them.

## Validate with KQL

Run `queries/rogue-principal-access.kql`. It should return two rows for `shadow-sync-prod-sp`: Key Vault Secrets Officer and Storage Blob Data Owner. Then run `queries/high-value-exposure.kql` to summarize all high-value access paths.

An empty result normally means the table suffix differs, the connector has not refreshed, the fixture was not loaded, or the source schema changed. It does not by itself prove that no risky path exists.

## Build and validate the graph

1. In the Microsoft Sentinel VS Code extension, create a notebook and select a Sentinel Spark pool.
2. Model `EntraServicePrincipal` / `EntraUser` source nodes, `AzureResource` target nodes, and `CAN_ACCESS` edges from the two federated tables.
3. Materialize the graph with a scheduled graph job; interactive notebook graphs are temporary.
4. In **Microsoft Sentinel > Graphs**, open the graph and run `queries/rogue-principal-path.gql`.
5. Confirm the result contains one rogue service principal, two resources, and two directed access edges. Validate the same facts in table view before relying on the visualization.

The repository intentionally does not include generated notebook authentication state or a tenant-specific graph definition. Graph-builder APIs and permissions are preview features, so use the current Microsoft-provided notebook template in the extension rather than copying stale generated SDK calls.

## Cost, safety, and limitations

- Federation avoids analytics-tier ingestion/storage for the external context, but data lake queries, advanced insights, graph operations, underlying storage, Key Vault, and Spark/compute can incur charges.
- The connector is read-only, but its current public-access requirement expands network exposure. Restrict the service principal to read-only access and re-tighten Key Vault networking after connector creation where supported.
- Table updates can take time to appear. Validate freshness before treating results as incident evidence.
- This synthetic four-row dataset proves the workflow, not complete RBAC reachability. Nested groups, deny assignments, management-group inheritance, PIM eligibility, cross-tenant access, and application permissions need additional sources and modeling.
- Custom graphs and data federation remain preview capabilities as of the verification date.

## Cleanup

1. Delete the federation connector instance from **Data federation > My connectors**.
2. Delete the scheduled custom-graph job and graph instance.
3. Remove the two disposable source tables or the entire lab container/storage account.
4. Delete the Key Vault secret and service principal if they were created only for this lab.
5. Review costs and role assignments. Do not delete the Sentinel workspace unless it was independently created as disposable infrastructure.

## Troubleshooting and references

- [Set up federated data connectors](https://learn.microsoft.com/azure/sentinel/datalake/data-federation-setup)
- [Create custom graphs](https://learn.microsoft.com/azure/sentinel/datalake/create-custom-graphs)
- [Visualize custom graphs](https://learn.microsoft.com/azure/sentinel/datalake/graph-visualization)
- [Custom graph overview](https://learn.microsoft.com/azure/sentinel/datalake/custom-graphs-overview)
