# GCP onboarding (read-only)

CloudRanger's agent needs a working `gcloud` CLI with viewer-level access.

```bash
gcloud auth login
gcloud config set project <project-id>   # or rely on --project in commands
```

Grant the identity **`roles/viewer`** on each project to scan. For the seed
catalog specifically, `roles/viewer` covers:

- `gcloud storage buckets list` / `buckets get-iam-policy`
- `gcloud compute instances|firewall-rules|networks list`
- `gcloud sql instances list`
- `gcloud iam service-accounts list` / `keys list`
- `gcloud projects get-iam-policy`

Avoid service account keys; use your user credentials or workload identity.
CloudRanger never sees or stores any credential material.

All plan commands carry an explicit `--project <scopeId>`, so multi-project
scanning is just multiple scans with different scope IDs.
