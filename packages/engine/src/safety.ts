/**
 * Read-only command safety validation.
 *
 * Every collector command handed to an agent must be a read-only cloud CLI
 * invocation. This is enforced structurally at catalog load time and again
 * before a plan is returned via MCP. Defence in depth: the agent is also
 * instructed (via prompts/resources) to refuse anything mutating.
 */

const SHELL_METACHARACTERS = /[;&|><`$()\n\\]/;

/** AWS CLI: service subcommand must start with a read-only verb. */
const AWS_READONLY =
  /^aws\s+[a-z0-9-]+\s+(list|describe|get|lookup|search|scan-status|batch-get)[a-z0-9-]*(\s|$)/;

/** Azure CLI: last action token must be list/show/get variants. */
const AZ_READONLY = /^az\s+[a-z0-9- ]*\b(list|show|get-access-token)\b/;
const AZ_FORBIDDEN =
  /\b(create|update|delete|set|add|remove|start|stop|restart|deploy|import|export|purge|assign|grant|revoke|upload)\b/;

/** gcloud: action must be list/describe/get-iam-policy etc. */
const GCLOUD_READONLY = /^gcloud\s+[a-z0-9- ]*\b(list|describe|get-iam-policy|get-ancestors|get)\b/;
const GCLOUD_FORBIDDEN =
  /\b(create|update|delete|set-iam-policy|add-iam-policy-binding|remove-iam-policy-binding|deploy|import|export|start|stop|reset|patch)\b/;

const PLACEHOLDER = /\{(region|resource|account|project|subscription)\}/g;

export interface CommandSafetyResult {
  safe: boolean;
  reason?: string;
}

export function validateReadOnlyCommand(command: string): CommandSafetyResult {
  const stripped = command.replace(PLACEHOLDER, "PLACEHOLDER");
  if (SHELL_METACHARACTERS.test(stripped)) {
    return { safe: false, reason: "command contains shell metacharacters" };
  }
  if (stripped.startsWith("aws ")) {
    if (!AWS_READONLY.test(stripped)) {
      return { safe: false, reason: "aws command does not start with a read-only verb" };
    }
    return { safe: true };
  }
  if (stripped.startsWith("az ")) {
    if (AZ_FORBIDDEN.test(stripped)) {
      return { safe: false, reason: "az command contains a mutating verb" };
    }
    if (!AZ_READONLY.test(stripped)) {
      return { safe: false, reason: "az command is not a recognised read-only action" };
    }
    return { safe: true };
  }
  if (stripped.startsWith("gcloud ") || stripped.startsWith("gsutil ")) {
    if (GCLOUD_FORBIDDEN.test(stripped)) {
      return { safe: false, reason: "gcloud command contains a mutating verb" };
    }
    if (stripped.startsWith("gsutil ")) {
      // Only iam get / ls are allowed for gsutil.
      if (!/^gsutil\s+(iam\s+get|ls)\b/.test(stripped)) {
        return { safe: false, reason: "gsutil command is not read-only" };
      }
      return { safe: true };
    }
    if (!GCLOUD_READONLY.test(stripped)) {
      return { safe: false, reason: "gcloud command is not a recognised read-only action" };
    }
    return { safe: true };
  }
  return { safe: false, reason: "command must invoke aws, az, gcloud or gsutil" };
}

/**
 * Exact-match allowlist of idempotent preparation commands. These do not pass
 * the read-only verb rules but mutate nothing an operator cares about:
 * generate-credential-report only (re)builds AWS's own server-side report so
 * the subsequent get-credential-report has something to return. Additions
 * require a threat-model update.
 */
const PREPARATION_COMMANDS = new Set(["aws iam generate-credential-report"]);

export function validatePreparationCommand(command: string): CommandSafetyResult {
  if (SHELL_METACHARACTERS.test(command)) {
    return { safe: false, reason: "preparation command contains shell metacharacters" };
  }
  if (!PREPARATION_COMMANDS.has(command.trim())) {
    return { safe: false, reason: "preparation command is not on the exact-match allowlist" };
  }
  return { safe: true };
}

/**
 * Validate a parameter value substituted into a command placeholder.
 * Region names, account IDs, resource names — strict charset, no spaces.
 */
export function validateParamValue(value: string): boolean {
  return /^[A-Za-z0-9._\-:/@]{1,256}$/.test(value);
}
