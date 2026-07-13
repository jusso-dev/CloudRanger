import type {
  CollectorDefinition,
  ControlDefinition,
  EvaluationStatus,
  EvidenceRecord,
} from "./types.js";
import { evaluateControls } from "./evaluate.js";
import { z } from "zod";

/**
 * Fixture-driven control tests. Each control ships cases containing real
 * (sanitised) CLI JSON output; the runner asserts the deterministic outcome.
 */

export const fixtureFileSchema = z
  .object({
    controlId: z.string(),
    cases: z
      .array(
        z
          .object({
            name: z.string(),
            expected: z.enum(["pass", "fail", "not_applicable", "error", "no_results"]),
            /** Which resource's status to assert; default: single result. */
            resourceId: z.string().optional(),
            /** Parameter overrides for this case (parameterised controls). */
            parameters: z.record(z.string(), z.unknown()).optional(),
            records: z.array(
              z
                .object({
                  collectorId: z.string(),
                  region: z.string().optional(),
                  resourceKey: z.string().optional(),
                  output: z.unknown(),
                  errorText: z.string().optional(),
                  exitCode: z.number().int(),
                })
                .strict(),
            ),
          })
          .strict(),
      )
      .min(1),
  })
  .strict();

export type FixtureFile = z.infer<typeof fixtureFileSchema>;

export interface FixtureCaseResult {
  controlId: string;
  caseName: string;
  ok: boolean;
  expected: string;
  actual: string;
  detail?: string;
}

const FIXED_NOW = new Date("2026-01-01T00:00:00Z");
const FIXED_COLLECTED_AT = "2025-12-31T00:00:00Z";

export function runFixtureFile(
  fixture: FixtureFile,
  controls: ControlDefinition[],
  collectors: Map<string, CollectorDefinition>,
): FixtureCaseResult[] {
  const control = controls.find((c) => c.id === fixture.controlId);
  if (!control) {
    return [
      {
        controlId: fixture.controlId,
        caseName: "*",
        ok: false,
        expected: "control exists",
        actual: "unknown control id",
      },
    ];
  }
  const results: FixtureCaseResult[] = [];
  for (const testCase of fixture.cases) {
    const records: EvidenceRecord[] = testCase.records.map((r) => ({
      ...r,
      output: r.output ?? null,
      collectedAt: FIXED_COLLECTED_AT,
    }));
    const { results: evaluations } = evaluateControls(
      [control],
      collectors,
      { provider: control.provider, scopeId: "fixture-scope", records },
      {
        now: FIXED_NOW,
        parameters: testCase.parameters ? { [control.id]: testCase.parameters } : undefined,
      },
    );
    let actual: EvaluationStatus | "no_results" | "ambiguous";
    if (testCase.resourceId) {
      actual =
        evaluations.find((e) => e.resourceId === testCase.resourceId)?.status ?? "no_results";
    } else if (evaluations.length === 1) {
      actual = evaluations[0]!.status;
    } else if (evaluations.length === 0) {
      actual = "no_results";
    } else {
      actual = "ambiguous";
    }
    results.push({
      controlId: fixture.controlId,
      caseName: testCase.name,
      ok: actual === testCase.expected,
      expected: testCase.expected,
      actual,
      detail:
        actual === "ambiguous"
          ? `case produced ${evaluations.length} results; specify resourceId`
          : undefined,
    });
  }
  return results;
}
