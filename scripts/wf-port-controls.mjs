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
    resourceIdField: <field identifying the resource. Use "$resourceKey" for per_resource collectors; "$scope" for account/subscription/project-level single checks>
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
        "resourceId": "<optional; which resource's status to assert when a case yields multiple>",
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

OUTPUT: return collectorsYaml (a YAML doc with a 'collectors:' list of ONLY new collectors, or "collectors: []"), controlsYaml (a YAML doc with a 'controls:' list), fixturesJson (a JSON array), controlIds (list of ids you produced), and excludedChecks (checks you deliberately skipped with a one-line reason). Everything must be valid and internally consistent: every control's collector must exist (new or in the provided existing list), every control must have a fixture with >=1 pass and >=1 fail case, and every fixture output must be a realistic CLI shape.`;

const EXISTING_AWS_COLLECTORS = `Existing AWS collectors (reference by id, DO NOT redefine):
aws.cloudtrail.describe_trails (single), aws.cloudtrail.get_trail_status (per_resource of describe_trails via TrailARN), aws.config.describe_configuration_recorder_status (single regional), aws.dynamodb.list_tables (single regional), aws.dynamodb.describe_continuous_backups (per_resource), aws.ec2.describe_instances (single regional; Reservations[].Instances), aws.ec2.describe_security_groups (single regional; SecurityGroups), aws.ec2.describe_snapshots_self (single regional; Snapshots), aws.ec2.describe_volumes (single regional; Volumes), aws.ec2.get_ebs_encryption_by_default (single regional), aws.efs.describe_file_systems (single regional; FileSystems), aws.guardduty.list_detectors (single regional; DetectorIds), aws.iam.get_account_password_policy (single; PasswordPolicy), aws.iam.get_account_summary (single; SummaryMap), aws.iam.list_access_keys (per_resource of list_users), aws.iam.list_mfa_devices (per_resource of list_users), aws.iam.list_users (single; Users), aws.kms.list_keys (single regional; Keys), aws.kms.get_key_rotation_status (per_resource), aws.rds.describe_db_instances (single regional; DBInstances), aws.s3.list_buckets (single; Buckets), aws.s3.get_public_access_block/get_bucket_encryption/get_bucket_versioning (per_resource of list_buckets via Name), aws.s3control.get_account_public_access_block (single; needs {account}), aws.secretsmanager.list_secrets (single regional; SecretList), aws.sns.list_topics (single regional; Topics), aws.sns.get_topic_attributes (per_resource), aws.sqs.list_queues (single regional; QueueUrls), aws.sqs.get_queue_attributes (per_resource).`;

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
      `${CONTRACT}\n\n${provider === "aws" ? EXISTING_AWS_COLLECTORS : ""}\n\nYOUR ASSIGNMENT:\nProvider: ${provider}\nService: ${slice.service}\nPort approximately ${slice.target} of the highest-value, most groundable Prowler/CIS checks for ${provider} ${slice.service}. Focus: ${slice.focus}\nAssign control ids CR-${provider.toUpperCase()}-${slice.idService || slice.service.toUpperCase().replace(/[^A-Z0-9]/g, "")}-NNN starting at NNN=${String(slice.start).padStart(3, "0")} and incrementing. Prefer high/critical exposure, identity, encryption, logging and resilience checks. Exclude anything not groundable from a single read-only CLI call (note why in excludedChecks). Produce controls + any new collectors + fixtures per the contract.`,
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
