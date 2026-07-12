# Azure onboarding (read-only)

CloudRanger's agent needs a working `az` CLI with **Reader** access.

```bash
az login                        # or az login --use-device-code
az account show                 # note "id" — the subscription scopeId
az account set --subscription <id>   # ensure the right subscription
```

Grant the identity the built-in **`Reader`** role at subscription scope (or
management-group scope for breadth). `Reader` covers every collector in the
seed catalog (`az storage account list`, `az network nsg list`,
`az keyvault list/show`, `az sql server list`, `az vm list`,
`az webapp list`).

Note: `az keyvault show` needs only management-plane read — no data-plane
(secrets/keys) permissions are used anywhere.

The scan workflow instructs the agent to confirm `az account show` matches
the requested scope before collecting; if you manage multiple
subscriptions, scan them one at a time.
