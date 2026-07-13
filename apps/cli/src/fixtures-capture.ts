import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { customCatalogDir, loadDefaultCatalog } from "@cloudranger/catalog";
import {
  createSanitizer,
  runFixtureFile,
  validateParamValue,
  validatePreparationCommand,
  validateReadOnlyCommand,
  type CollectorDefinition,
  type ControlDefinition,
} from "@cloudranger/engine";

/**
 * `cloudranger fixtures capture` — turn real (or piped) CLI output into a
 * sanitised fixture case for a control, validating the expected verdict
 * against the engine before anything is written. Raw output only ever lives
 * in memory; the sanitised copy is what reaches disk.
 */

export interface CaptureOptions {
  control?: string;
  expected?: string;
  name?: string;
  resource?: string;
  region?: string;
  resourceKey?: string;
  scope?: string;
  fromFile?: string;
  run?: boolean;
  output?: string;
}

const EXPECTED = new Set(["pass", "fail", "not_applicable", "error", "no_results"]);

function renderCommand(
  collector: CollectorDefinition,
  options: CaptureOptions,
): { command: string } {
  let command = collector.command;
  if (collector.regional) {
    if (!options.region) throw new Error("collector is regional; pass --region");
    if (!validateParamValue(options.region)) throw new Error("invalid --region value");
    command = command.replaceAll("{region}", options.region);
  }
  if (collector.kind === "per_resource") {
    if (!options.resourceKey) {
      throw new Error("collector is per_resource; pass --resource-key");
    }
    if (!validateParamValue(options.resourceKey)) throw new Error("invalid --resource-key value");
    command = command.replaceAll("{resource}", options.resourceKey);
  }
  if (options.scope) {
    if (!validateParamValue(options.scope)) throw new Error("invalid --scope value");
    command = command
      .replaceAll("{account}", options.scope)
      .replaceAll("{project}", options.scope)
      .replaceAll("{subscription}", options.scope);
  }
  if (/\{(region|resource|account|project|subscription)\}/.test(command)) {
    throw new Error(`command still contains placeholders after substitution: ${command}`);
  }
  const safety = validateReadOnlyCommand(command);
  if (!safety.safe) throw new Error(`refusing to run: ${safety.reason}`);
  return { command };
}

function execCapture(
  command: string,
  timeoutMs: number,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    // Safe: the command passed read-only validation (verb allowlist, no shell
    // metacharacters) immediately before this call.
    const child = spawn(command, { shell: true, timeout: timeoutMs });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => (stdout += chunk.toString()));
    child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString()));
    child.on("error", reject);
    child.on("close", (code) => resolve({ stdout, stderr, exitCode: code ?? 1 }));
  });
}

async function readStdin(): Promise<string> {
  let data = "";
  for await (const chunk of process.stdin) data += chunk;
  return data;
}

export async function fixturesCapture(options: CaptureOptions): Promise<number> {
  if (!options.control || !options.expected || !EXPECTED.has(options.expected)) {
    console.error(
      "fixtures capture requires --control <id> and --expected pass|fail|not_applicable|error",
    );
    return 1;
  }
  const catalog = loadDefaultCatalog();
  const control = catalog.controls.find((c) => c.id === options.control) as
    ControlDefinition | undefined;
  if (!control) {
    console.error(`unknown control: ${options.control}`);
    return 1;
  }
  const collector = catalog.collectors.get(control.collector);
  if (!collector) {
    console.error(`control has unknown collector: ${control.collector}`);
    return 1;
  }

  let rawOutput: unknown = null;
  let errorText: string | undefined;
  let exitCode = 0;
  if (options.run) {
    if (collector.prepareCommand) {
      const prepSafety = validatePreparationCommand(collector.prepareCommand);
      if (!prepSafety.safe) {
        console.error(`refusing prepare command: ${prepSafety.reason}`);
        return 1;
      }
      await execCapture(collector.prepareCommand, collector.timeoutMs ?? 120_000);
    }
    const { command } = renderCommand(collector, options);
    console.error(`running: ${command}`);
    const result = await execCapture(command, collector.timeoutMs ?? 120_000);
    exitCode = result.exitCode;
    if (exitCode === 0) {
      rawOutput = JSON.parse(result.stdout);
    } else {
      errorText = result.stderr.slice(0, 10_000);
    }
  } else {
    const text = options.fromFile ? readFileSync(options.fromFile, "utf8") : await readStdin();
    if (!text.trim()) {
      console.error("no input: pipe CLI JSON output, or use --from-file / --run");
      return 1;
    }
    rawOutput = JSON.parse(text);
  }

  const sanitizer = createSanitizer();
  const sanitizedOutput = rawOutput === null ? null : sanitizer.sanitize(rawOutput);
  const sanitizedError = errorText ? (sanitizer.sanitize(errorText) as string) : undefined;
  const sanitizedResource = options.resource
    ? (sanitizer.sanitize(options.resource) as string)
    : undefined;

  const testCase = {
    name:
      options.name ??
      `captured ${options.expected} case (${new Date().toISOString().slice(0, 10)})`,
    expected: options.expected as "pass" | "fail" | "not_applicable" | "error" | "no_results",
    ...(sanitizedResource ? { resourceId: sanitizedResource } : {}),
    records: [
      {
        collectorId: collector.id,
        ...(options.region ? { region: options.region } : {}),
        ...(options.resourceKey
          ? { resourceKey: sanitizer.sanitize(options.resourceKey) as string }
          : {}),
        output: sanitizedOutput,
        ...(sanitizedError ? { errorText: sanitizedError } : {}),
        exitCode,
      },
    ],
  };

  // Validate the verdict BEFORE writing: a fixture that disagrees with its
  // declared expectation must never land on disk.
  const results = runFixtureFile(
    { controlId: control.id, cases: [testCase] },
    catalog.controls,
    catalog.collectors,
  );
  const verdict = results[0]!;
  if (!verdict.ok) {
    console.error(
      `verdict mismatch: expected ${verdict.expected}, engine says ${verdict.actual}${verdict.detail ? ` (${verdict.detail})` : ""}. Nothing written.`,
    );
    return 1;
  }

  const outputPath = options.output ?? join(customCatalogDir(), "fixtures", `${control.id}.json`);
  let fixtures: Array<{ controlId: string; cases: unknown[] }> = [];
  if (existsSync(outputPath)) {
    fixtures = JSON.parse(readFileSync(outputPath, "utf8"));
  }
  let entry = fixtures.find((f) => f.controlId === control.id);
  if (!entry) {
    entry = { controlId: control.id, cases: [] };
    fixtures.push(entry);
  }
  entry.cases.push(testCase);
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, JSON.stringify(fixtures, null, 2) + "\n");

  const replaced = sanitizer.replacements().length;
  console.log(
    `wrote ${control.id} / "${testCase.name}" (${options.expected}) to ${outputPath}` +
      (replaced > 0 ? ` — sanitised ${replaced} distinct identifier(s)` : ""),
  );
  console.log("run: cloudranger catalog test");
  return 0;
}
