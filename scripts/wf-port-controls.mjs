export const meta = {
  name: "port-cloud-controls",
  description: "Port Prowler/CIS cloud security checks into grounded CloudRanger controls + collectors + fixtures",
  phases: [
    { title: "Generate", detail: "one agent per service slice ports checks" },
    { title: "Verify", detail: "adversarial grounding review per slice" },
  ],
};

// args: { provider: "aws"|"azure"|"gcp", slices: [ { service, start, target, focus } ] }
const parsedArgs = typeof args === "string" ? JSON.parse(args) : args;
const provider = parsedArgs.provider;
const slices = parsedArgs.slices;

const CONTRACT = `You are porting cloud security posture checks into CloudRanger's control catalog format.

CloudRanger is a deterministic CSPM engine. An LLM agent runs READ-ONLY cloud CLI commands and submits the JSON output; a rule engine evaluates declarative controls against that JSON. You are producing controls, the collectors (CLI commands) they need, and fixtures (test cases) that prove them.

ABSOLUTE RULES:
- Ground every control in the REAL CLI JSON shape. Use the actual field names ${provider} CLI returns for describe/list/get/show. Do NOT guess field names. If unsure of a shape, exclude the check (report it in excludedChecks) rather than invent it.
- Collector commands MUST be read-only: aws list/describe/get*, az list/show/get*, gcloud list/describe/get-iam-policy. No create/update/delete/set/put/add/remove. No shell metacharacters (; & | > \` $ ( )). No pipes. Output must be JSON (--output json for aws/az, --format json for gcloud).
- Exclude any check that needs: external services (Shodan), paid API-only data, data-plane/secret VALUES, or non-CLI sources. Only checks groundable from one read-only CLI call.
- Do NOT redefine existing collectors (listed below) — reference them by id in controls. Only define NEW collectors you introduce.

CONTROL SCHEMA (YAML, under a top-level 'controls:' list). Every field is required unless marked optional:
  - id: CR-${provider.toUpperCase()}-<SERVICE>-<NNN>   (SERVICE uppercase alnum; NNN zero-padded 3 digits, in your assigned range)
    version: 1.0.0
    provider: ${provider}
    service: <lowercase service>
    title: <one line desired state>
    description: <1-2 sentences>
    rationale: <the realistic risk if this fails>
    severity: informational|low|medium|high|critical
    categories: [<kebab tags e.g. identity, encryption, public-exposure, logging, network, resilience>]
    source: { engine: prowler, id: <exact prowler snake_case check id>, license: Apache-2.0 }
    collector: <collector id this control evaluates>
    resourcesPath: <optional; path within collector output to the resource ARRAY. Use "$" when the CLI output root IS the array (az/gcloud list style) OR the whole output is one account-level object. Support "A[].B" to flatten nested arrays e.g. Reservations[].Instances. OMIT entirely for per_resource collectors.>
    aggregate: <optional bool. Set true for an ACCOUNT/SUBSCRIPTION/PROJECT-level check that must reason over the WHOLE inventory at once — e.g. "does ANY log profile capture all categories", "does a catch-all log sink exist", "is there a security contact". With aggregate:true the entire collector output (even a top-level array) is treated as ONE resource, so passWhen uses anyItem/noneItem/allItems over path "$" (each item's condition paths are relative to the item). Pair with resourceIdField "$scope" and OMIT resourcesPath. Do NOT use aggregate for per-resource checks (each bucket/VM/server is its own resource — use the normal array split).>
    resourceIdField: <field identifying the resource. Use "$resourceKey" for per_resource collectors; "$scope" for account/subscription/project-level single checks (single-object OR aggregate:true over an array)>
    resourceNameField: <optional display-name field>
    applicableWhen: <optional expression; resource only evaluated if true>
    passWhen: <expression; resource PASSES when true>
    onError: <optional list of { contains: <substring of CLI error>, status: pass|fail|not_applicable|error, message?: string }>
    failMessage: <shown when failing>
    passMessage: <shown when passing>
    remediation: { summary: <one line>, steps: [<operator step>, ...], verifyCommand: <optional read-only command> }
    compliance: [ { framework: <e.g. cis-aws-foundations>, version?: <e.g. "3.0">, controls: [<section ids>] } ]   (use [] if unknown)
    references: [ <url> ]   (at least one; provider docs)

EXPRESSION OPERATORS (the ONLY allowed ops; compose freely):
  { op: equals, path, value } | notEquals | { op: exists, path } | notExists
  { op: in, path, values: [...] } | notIn | { op: contains, path, value } | notContains
  { op: startsWith|endsWith, path, value } | { op: gt|gte|lt|lte, path, value:<number> }
  { op: daysSinceGt|daysSinceLt, path, value:<number> }   (path is an ISO date; days since it)
  { op: matches, path, pattern:<safe regex> } | { op: lengthEquals|lengthGt, path, value:<int> } | { op: isEmpty, path }
  { op: isPublicCidr, path }   (true for 0.0.0.0/0, ::/0, *, any, internet)
  { op: portIncludes, fromPath, toPath, value:<int> }   (AWS SG style FromPort/ToPort; absent bounds/-1 = all ports)
  { op: portStringIncludes, path, value:<int> }   (Azure/GCP style "22", "20-25", "*", or array thereof)
  { op: and|or, exprs: [...] } | { op: not, expr: {...} }
  { op: anyItem|allItems|noneItem, path, condition: {...} }   (quantify over an array at path; condition paths are RELATIVE to each item; use "$" to refer to a scalar array item)
Paths are dot-paths with numeric indexes (a.b.0.c). Scalars coerce loosely (true=="true", 1=="1"). MISSING data never satisfies a positive predicate — express "absent = fail" with notExists explicitly.

COLLECTOR SCHEMA (YAML under top-level 'collectors:' list; emit ONLY new ones):
  - id: ${provider}.<service>.<snake_verb>
    provider: ${provider}
    service: <service>
    description: <what it collects>
    kind: single | per_resource
    command: <read-only CLI; use {region} for aws regional, {resource} for per_resource iteration, {project} for gcloud, {account}/{subscription} where needed>
    regional: <true|false>   (aws regional commands must include {region})
    parent: <required for per_resource: { collector: <parent id>, itemsPath: <path to array in parent output; "$" if parent output IS the array>, resourceField: <field on each item used as {resource}; "$" if items are strings> }>
    outputFormat: json
    notes: <optional; permissions, quirks, error behaviour>

FIXTURES (JSON array; one object per control). Each control needs >=1 pass case AND >=1 fail case; add not_applicable/error where the control uses applicableWhen/onError:
  [ { "controlId": "<id>", "cases": [
      { "name": "<desc>", "expected": "pass|fail|not_applicable|error|no_results",
        "resourceId": "<optional; which resource's status to assert when a case yields multiple. NEVER set this to the literal '$scope' — for aggregate/$scope checks the unit's id resolves to the real account/subscription/project id, so a '$scope' assertion never matches and the case yields no_results. For aggregate checks OMIT resourceId entirely.>",
        "records": [ { "collectorId": "<id>", "region": "<optional>", "resourceKey": "<for per_resource>",
                      "output": <the REAL-SHAPE parsed JSON the CLI would return>, "errorText": "<for failures>", "exitCode": 0 } ] } ] } ]
Fixture output MUST be the realistic CLI JSON shape (this is how grounding is proven). For an error case set output null, exitCode non-zero, and errorText to the real CLI error string.

TWO REAL EXAMPLES (study the shapes):

Example A — single collector returning an object with a resource array, evaluated across items:
controls:
  - id: CR-AWS-EC2-001
    version: 1.0.0
    provider: aws
    service: ec2
    title: No security group allows SSH from the internet
    description: No ingress rule permits TCP 22 from 0.0.0.0/0 or ::/0.
    rationale: World-open SSH invites brute forcing and is a standard initial-access vector.
    severity: high
    categories: [network, public-exposure]
    source: { engine: prowler, id: ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22, license: Apache-2.0 }
    collector: aws.ec2.describe_security_groups
    resourcesPath: SecurityGroups
    resourceIdField: GroupId
    resourceNameField: GroupName
    passWhen:
      op: noneItem
      path: IpPermissions
      condition:
        op: and
        exprs:
          - { op: portIncludes, fromPath: FromPort, toPath: ToPort, value: 22 }
          - op: or
            exprs:
              - { op: anyItem, path: IpRanges, condition: { op: isPublicCidr, path: CidrIp } }
              - { op: anyItem, path: Ipv6Ranges, condition: { op: isPublicCidr, path: CidrIpv6 } }
    failMessage: Security group allows SSH (22/tcp) from the internet.
    passMessage: No internet-open SSH ingress.
    remediation: { summary: Restrict port 22., steps: [Replace 0.0.0.0/0 with specific ranges.], verifyCommand: aws ec2 describe-security-groups --region <region> --output json }
    compliance: [ { framework: cis-aws-foundations, version: "3.0", controls: ["5.2"] } ]
    references: [ https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules.html ]
collector used (already exists — do NOT redefine): aws.ec2.describe_security_groups (single, regional, command "aws ec2 describe-security-groups --region {region} --output json")
fixture:
[ { "controlId": "CR-AWS-EC2-001", "cases": [
  { "name": "fails open ssh", "expected": "fail", "records": [ { "collectorId": "aws.ec2.describe_security_groups", "region": "us-east-1", "exitCode": 0, "output": { "SecurityGroups": [ { "GroupId": "sg-1", "GroupName": "open", "IpPermissions": [ { "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [ { "CidrIp": "0.0.0.0/0" } ], "Ipv6Ranges": [] } ] } ] } } ] },
  { "name": "passes restricted", "expected": "pass", "records": [ { "collectorId": "aws.ec2.describe_security_groups", "region": "us-east-1", "exitCode": 0, "output": { "SecurityGroups": [ { "GroupId": "sg-2", "GroupName": "ok", "IpPermissions": [ { "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [ { "CidrIp": "10.0.0.0/8" } ], "Ipv6Ranges": [] } ] } ] } } ] } ] } ]

Example B — per_resource collector (one command per parent item), with onError mapping:
collectors:
  - id: aws.s3.get_public_access_block
    provider: aws
    service: s3
    description: Public access block for one bucket.
    kind: per_resource
    command: aws s3api get-public-access-block --bucket {resource} --output json
    regional: false
    parent: { collector: aws.s3.list_buckets, itemsPath: Buckets, resourceField: Name }
    outputFormat: json
controls:
  - id: CR-AWS-S3-001
    version: 1.0.0
    provider: aws
    service: s3
    title: S3 bucket blocks all public access
    description: All four bucket public access block settings are enabled.
    rationale: Public object storage is a top cause of data exposure.
    severity: high
    categories: [storage, public-exposure]
    source: { engine: prowler, id: s3_bucket_public_access_block, license: Apache-2.0 }
    collector: aws.s3.get_public_access_block
    resourceIdField: $resourceKey
    passWhen:
      op: and
      exprs:
        - { op: equals, path: PublicAccessBlockConfiguration.BlockPublicAcls, value: true }
        - { op: equals, path: PublicAccessBlockConfiguration.IgnorePublicAcls, value: true }
        - { op: equals, path: PublicAccessBlockConfiguration.BlockPublicPolicy, value: true }
        - { op: equals, path: PublicAccessBlockConfiguration.RestrictPublicBuckets, value: true }
    onError:
      - { contains: NoSuchPublicAccessBlockConfiguration, status: fail, message: No public access block configured. }
      - { contains: AccessDenied, status: error }
    failMessage: Bucket does not block all public access.
    passMessage: Bucket blocks all public access.
    remediation: { summary: Enable all four settings., steps: [Enable BlockPublicAcls/IgnorePublicAcls/BlockPublicPolicy/RestrictPublicBuckets.] }
    compliance: [ { framework: cis-aws-foundations, version: "3.0", controls: ["2.1.4"] } ]
    references: [ https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html ]
fixture (per_resource uses resourceKey and $resourceKey as the id):
[ { "controlId": "CR-AWS-S3-001", "cases": [
  { "name": "pass all on", "expected": "pass", "records": [ { "collectorId": "aws.s3.get_public_access_block", "resourceKey": "b1", "exitCode": 0, "output": { "PublicAccessBlockConfiguration": { "BlockPublicAcls": true, "IgnorePublicAcls": true, "BlockPublicPolicy": true, "RestrictPublicBuckets": true } } } ] },
  { "name": "fail missing config", "expected": "fail", "records": [ { "collectorId": "aws.s3.get_public_access_block", "resourceKey": "b2", "exitCode": 254, "output": null, "errorText": "An error occurred (NoSuchPublicAccessBlockConfiguration)" } ] } ] } ]

Account-level single check: collector kind single, resourceIdField: $scope, resourcesPath "$" and the output object is the single resource (e.g. aws iam get-account-summary → evaluate SummaryMap fields).

Aggregate account-level check over an inventory ARRAY (use when the pass condition is "does ANY / do NONE of the items in the whole account satisfy X"): set aggregate: true, resourceIdField: $scope, OMIT resourcesPath, and quantify with anyItem/noneItem/allItems over path "$". Example — a project has at least one catch-all log sink:
  - id: CR-GCP-LOGGING-110
    ...
    collector: gcp.logging.sinks_list
    aggregate: true
    resourceIdField: $scope
    passWhen: { op: anyItem, path: "$", condition: { op: and, exprs: [ { op: notEquals, path: disabled, value: true }, { op: isEmpty, path: filter } ] } }
Fixture: ONE record whose output is the whole array; a pass case where an item matches, and a fail case where the array is empty or no item matches (the aggregate unit still evaluates, yielding fail — not no_results).

OUTPUT: return collectorsYaml (a YAML doc with a 'collectors:' list of ONLY new collectors, or "collectors: []"), controlsYaml (a YAML doc with a 'controls:' list), fixturesJson (a JSON array), controlIds (list of ids you produced), and excludedChecks (checks you deliberately skipped with a one-line reason). Everything must be valid and internally consistent: every control's collector must exist (new or in the provided existing list), every control must have a fixture with >=1 pass and >=1 fail case, and every fixture output must be a realistic CLI shape.`;

const EXISTING_AWS_COLLECTORS = `Existing AWS collectors (reference by id, DO NOT redefine — redefining ANY bundled collector poisons the whole slice):
aws.accessanalyzer.list_analyzers, aws.apigateway.get_rest_apis, aws.apigateway.get_stages, aws.cloudfront.list_distributions, aws.cloudfront.get_distribution_config, aws.cloudtrail.describe_trails, aws.cloudtrail.get_trail_status, aws.config.describe_configuration_recorder_status, aws.dms.describe_replication_instances, aws.dynamodb.list_tables, aws.dynamodb.describe_continuous_backups, aws.ec2.describe_addresses, aws.ec2.describe_images_self, aws.ec2.describe_instances (Reservations[].Instances), aws.ec2.describe_network_acls, aws.ec2.describe_security_groups (SecurityGroups), aws.ec2.describe_snapshot_attribute_cvp, aws.ec2.describe_snapshots_self, aws.ec2.describe_subnets, aws.ec2.describe_volumes, aws.ec2.describe_vpc_endpoints, aws.ec2.describe_vpcs, aws.ec2.get_ebs_encryption_by_default, aws.ecr.describe_repositories, aws.ecr.get_lifecycle_policy, aws.ecr.get_repository_policy, aws.ecs.list_task_definitions, aws.ecs.describe_task_definition, aws.efs.describe_file_systems, aws.eks.list_clusters, aws.eks.describe_cluster, aws.elasticache.describe_replication_groups, aws.elbv2.describe_load_balancers, aws.elbv2.describe_load_balancer_attributes, aws.elbv2.get_web_acl_for_resource, aws.guardduty.list_detectors, aws.iam.get_account_authorization_details, aws.iam.get_account_password_policy, aws.iam.get_account_summary, aws.iam.list_access_keys, aws.iam.list_mfa_devices, aws.iam.list_server_certificates, aws.iam.list_users, aws.kms.list_keys, aws.kms.describe_key, aws.kms.get_key_policy, aws.kms.get_key_rotation_status, aws.lambda.list_functions, aws.lambda.get_function_concurrency, aws.lambda.get_function_url_config, aws.lambda.get_policy, aws.logs.describe_log_groups, aws.opensearch.list_domain_names, aws.opensearch.describe_domain, aws.rds.describe_db_clusters, aws.rds.describe_db_instances, aws.rds.describe_db_snapshots, aws.rds.describe_db_snapshot_attributes, aws.redshift.describe_clusters, aws.redshift.describe_cluster_parameters, aws.redshift.describe_logging_status, aws.s3.list_buckets, aws.s3.get_bucket_acl, aws.s3.get_bucket_encryption, aws.s3.get_bucket_lifecycle_configuration, aws.s3.get_bucket_logging, aws.s3.get_bucket_notification_configuration, aws.s3.get_bucket_versioning, aws.s3.get_object_lock_configuration, aws.s3.get_public_access_block, aws.s3control.get_account_public_access_block, aws.sagemaker.list_notebook_instances, aws.sagemaker.describe_notebook_instance, aws.secretsmanager.list_secrets, aws.sns.list_topics, aws.sns.get_topic_attributes, aws.sqs.list_queues, aws.sqs.get_queue_attributes.
Regional collectors use {region}. If your target service already has a collector above, REUSE it; only define NEW collectors for services not listed.`;

const EXISTING_AZURE_COLLECTORS = `Existing Azure collectors (reference by id, DO NOT redefine — redefining ANY bundled collector poisons the whole slice):
azure.storage.list_accounts, azure.storage.blob_service_properties_show (per_resource), azure.network.list_nsgs (each with securityRules[]), azure.keyvault.list, azure.keyvault.show (per_resource), azure.sql.list_servers, azure.sql.audit_policy_show (per_resource), azure.sql.firewall_rule_list (per_resource), azure.sql.ad_admin_list (per_resource), azure.vm.list, azure.vm.list_ip_addresses, azure.webapp.list, azure.webapp.config_show (per_resource), azure.aks.list, azure.acr.list, azure.cosmosdb.list, azure.disk.list, azure.security.pricings_list, azure.security.auto_provisioning.
Azure CLI note: 'az ... list --output json' returns a JSON ARRAY at the root — use resourcesPath "$". Subscription-level single checks use resourceIdField "$scope". Fields are camelCase (properties.supportsHttpsTrafficOnly, properties.minimumTlsVersion). Only define NEW collectors for services not listed above.`;

const EXISTING_GCP_COLLECTORS = `Existing GCP collectors (reference by id, DO NOT redefine — redefining ANY bundled collector poisons the whole slice):
gcp.storage.buckets_list, gcp.storage.bucket_iam_policy (per_resource), gcp.compute.instances_list, gcp.compute.firewall_rules_list, gcp.compute.networks_list, gcp.compute.subnets_list, gcp.compute.project_info (commonInstanceMetadata.items), gcp.sql.instances_list, gcp.iam.service_accounts_list, gcp.iam.service_account_keys_list (per_resource), gcp.project.iam_policy (bindings[], auditConfigs[]), gcp.container.clusters_list, gcp.dns.managed_zones_list.
gcloud note: 'gcloud ... list --format json' returns a JSON ARRAY at the root — use resourcesPath "$". Project-level single checks use resourceIdField "$scope". New collectors must include {project}. Only define NEW collectors for services not listed above.`;

const EXISTING_COLLECTORS =
  provider === "aws"
    ? EXISTING_AWS_COLLECTORS
    : provider === "azure"
      ? EXISTING_AZURE_COLLECTORS
      : provider === "gcp"
        ? EXISTING_GCP_COLLECTORS
        : "";

const SLICE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    service: { type: "string" },
    collectorsYaml: { type: "string" },
    controlsYaml: { type: "string" },
    fixturesJson: { type: "string" },
    controlIds: { type: "array", items: { type: "string" } },
    excludedChecks: { type: "array", items: { type: "string" } },
  },
  required: ["service", "collectorsYaml", "controlsYaml", "fixturesJson", "controlIds"],
};

const VERDICT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    service: { type: "string" },
    verdict: { enum: ["pass", "revise"] },
    shapeConfidence: { enum: ["high", "medium", "low"] },
    issues: { type: "array", items: { type: "string" } },
  },
  required: ["service", "verdict", "shapeConfidence", "issues"],
};

const results = await pipeline(
  slices,
  (slice) =>
    agent(
      `${CONTRACT}\n\n${EXISTING_COLLECTORS}\n\nYOUR ASSIGNMENT:\nProvider: ${provider}\nService: ${slice.service}\nPort approximately ${slice.target} of the highest-value, most groundable Prowler/CIS checks for ${provider} ${slice.service}. Focus: ${slice.focus}\nAssign control ids CR-${provider.toUpperCase()}-${slice.idService || slice.service.toUpperCase().replace(/[^A-Z0-9]/g, "")}-NNN starting at NNN=${String(slice.start).padStart(3, "0")} and incrementing. Prefer high/critical exposure, identity, encryption, logging and resilience checks. Exclude anything not groundable from a single read-only CLI call (note why in excludedChecks). Produce controls + any new collectors + fixtures per the contract.`,
      { label: `gen:${provider}:${slice.service}`, phase: "Generate", schema: SLICE_SCHEMA },
    ),
  (gen, slice) => {
    if (!gen) return null;
    return agent(
      `You are adversarially reviewing generated CloudRanger controls for grounding correctness. The controls claim to evaluate ${provider} ${slice.service} from real read-only CLI JSON.\n\nCONTROLS YAML:\n${gen.controlsYaml}\n\nNEW COLLECTORS YAML:\n${gen.collectorsYaml}\n\nFIXTURES JSON:\n${gen.fixturesJson}\n\nCheck rigorously and report issues:\n1. Is every collector command genuinely read-only (list/describe/get/show only, no mutating verbs, no shell metacharacters)? Flag any that are not.\n2. Does each passWhen reference field names/paths that the REAL ${provider} CLI actually returns for that command? Flag any invented/guessed shapes or wrong nesting. This is the most important check.\n3. Are fixture outputs realistic CLI JSON (correct casing, structure, types)? Flag fixtures that would not match real output.\n4. Does each control have >=1 pass and >=1 fail fixture case, and does the logic look correct (missing data does not accidentally pass)?\n5. Any severity or attribution that looks wrong.\nReturn verdict pass only if you are confident the shapes are real and the logic is sound; otherwise revise with specific issues. Rate shapeConfidence high/medium/low.`,
      { label: `verify:${provider}:${slice.service}`, phase: "Verify", schema: VERDICT_SCHEMA },
    ).then((verdict) => ({ slice: slice.service, generation: gen, verdict }));
  },
);

return results.filter(Boolean);
