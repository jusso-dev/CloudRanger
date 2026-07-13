import { z } from "zod";

export const providerSchema = z.enum(["aws", "azure", "gcp"]);
export const severitySchema = z.enum(["informational", "low", "medium", "high", "critical"]);

const pathString = z.string().min(1).max(300);

const paramRefSchema = z.object({ $param: z.string().min(1).max(64) }).strict();
const numberOrParam = z.union([z.number(), paramRefSchema]);
const intOrParam = z.union([z.number().int(), paramRefSchema]);

export const expressionSchema: z.ZodType<unknown> = z.lazy(() =>
  z.union([
    z.object({ op: z.literal("equals"), path: pathString, value: z.unknown() }).strict(),
    z.object({ op: z.literal("notEquals"), path: pathString, value: z.unknown() }).strict(),
    z.object({ op: z.literal("exists"), path: pathString }).strict(),
    z.object({ op: z.literal("notExists"), path: pathString }).strict(),
    z
      .object({ op: z.literal("in"), path: pathString, values: z.array(z.unknown()).min(1) })
      .strict(),
    z
      .object({ op: z.literal("notIn"), path: pathString, values: z.array(z.unknown()).min(1) })
      .strict(),
    z.object({ op: z.literal("contains"), path: pathString, value: z.string() }).strict(),
    z.object({ op: z.literal("notContains"), path: pathString, value: z.string() }).strict(),
    z.object({ op: z.literal("startsWith"), path: pathString, value: z.string() }).strict(),
    z.object({ op: z.literal("endsWith"), path: pathString, value: z.string() }).strict(),
    z.object({ op: z.literal("gt"), path: pathString, value: numberOrParam }).strict(),
    z.object({ op: z.literal("gte"), path: pathString, value: numberOrParam }).strict(),
    z.object({ op: z.literal("lt"), path: pathString, value: numberOrParam }).strict(),
    z.object({ op: z.literal("lte"), path: pathString, value: numberOrParam }).strict(),
    z.object({ op: z.literal("daysSinceGt"), path: pathString, value: numberOrParam }).strict(),
    z.object({ op: z.literal("daysSinceLt"), path: pathString, value: numberOrParam }).strict(),
    z.object({ op: z.literal("matches"), path: pathString, pattern: z.string().max(200) }).strict(),
    z.object({ op: z.literal("lengthEquals"), path: pathString, value: intOrParam }).strict(),
    z.object({ op: z.literal("lengthGt"), path: pathString, value: intOrParam }).strict(),
    z.object({ op: z.literal("isEmpty"), path: pathString }).strict(),
    z.object({ op: z.literal("isPublicCidr"), path: pathString }).strict(),
    z
      .object({
        op: z.literal("portIncludes"),
        fromPath: pathString,
        toPath: pathString,
        value: z.number().int().min(0).max(65535),
      })
      .strict(),
    z
      .object({
        op: z.literal("portStringIncludes"),
        path: pathString,
        value: z.number().int().min(0).max(65535),
      })
      .strict(),
    z.object({ op: z.literal("and"), exprs: z.array(expressionSchema).min(1) }).strict(),
    z.object({ op: z.literal("or"), exprs: z.array(expressionSchema).min(1) }).strict(),
    z.object({ op: z.literal("not"), expr: expressionSchema }).strict(),
    z.object({ op: z.literal("anyItem"), path: pathString, condition: expressionSchema }).strict(),
    z.object({ op: z.literal("allItems"), path: pathString, condition: expressionSchema }).strict(),
    z.object({ op: z.literal("noneItem"), path: pathString, condition: expressionSchema }).strict(),
    z
      .object({
        op: z.literal("relationshipExists"),
        itemsPath: pathString,
        localPath: pathString,
        localItemPath: pathString.optional(),
        foreignPath: pathString,
        condition: expressionSchema.optional(),
      })
      .strict(),
    z
      .object({
        op: z.literal("anyItemReferencedBy"),
        itemsPath: pathString,
        itemCondition: expressionSchema,
        itemValuePath: pathString,
        relatedPath: pathString,
      })
      .strict(),
  ]),
);

export const collectorSchema = z
  .object({
    id: z.string().regex(/^(aws|azure|gcp)\.[a-z0-9_]+\.[a-z0-9_]+$/),
    provider: providerSchema,
    service: z.string().min(1),
    description: z.string().min(1),
    kind: z.enum(["single", "per_resource"]),
    command: z.string().min(1).max(500),
    regional: z.boolean(),
    parent: z
      .object({
        collector: z.string(),
        itemsPath: z.string(),
        resourceField: z.string(),
      })
      .strict()
      .optional(),
    outputFormat: z.literal("json"),
    decode: z
      .object({ type: z.literal("base64Csv"), contentPath: z.string().min(1).max(300) })
      .strict()
      .optional(),
    prepareCommand: z.string().min(1).max(200).optional(),
    timeoutMs: z.number().int().positive().max(900_000).optional(),
    maxAttempts: z.number().int().min(1).max(10).optional(),
    initialBackoffMs: z.number().int().nonnegative().max(60_000).optional(),
    maxBackoffMs: z.number().int().nonnegative().max(300_000).optional(),
    maxConcurrency: z.number().int().min(1).max(32).optional(),
    notes: z.string().optional(),
  })
  .strict()
  .superRefine((c, ctx) => {
    if (c.kind === "per_resource" && !c.parent) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "per_resource collector requires parent",
      });
    }
    if (c.kind === "per_resource" && !c.command.includes("{resource}")) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "per_resource collector command must contain {resource}",
      });
    }
    if (c.regional && c.provider === "aws" && !c.command.includes("{region}")) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "regional aws collector command must contain {region}",
      });
    }
  });

export const controlSchema = z
  .object({
    id: z.string().regex(/^(CR|CUSTOM)-(AWS|AZURE|GCP)-[A-Z0-9]+-\d{3}$/),
    version: z.string().regex(/^\d+\.\d+\.\d+$/),
    provider: providerSchema,
    service: z.string().min(1),
    title: z.string().min(1).max(200),
    description: z.string().min(1),
    rationale: z.string().min(1),
    severity: severitySchema,
    categories: z.array(z.string()).min(1),
    source: z
      .object({
        engine: z.enum(["prowler", "trivy", "steampipe", "custom"]),
        id: z.string().min(1),
        license: z.string().min(1),
      })
      .strict(),
    collector: z.string().min(1),
    relatedCollectors: z
      .array(
        z
          .object({ collector: z.string().min(1), as: z.string().regex(/^[A-Za-z][A-Za-z0-9_]*$/) })
          .strict(),
      )
      .min(1)
      .optional(),
    parameters: z
      .record(
        z.string().regex(/^[a-z][A-Za-z0-9]{0,63}$/),
        z
          .object({
            type: z.enum(["number", "string", "boolean"]),
            description: z.string().min(1),
            default: z.union([z.number(), z.string(), z.boolean()]),
            min: z.number().optional(),
            max: z.number().optional(),
            enum: z
              .array(z.union([z.number(), z.string()]))
              .min(1)
              .optional(),
          })
          .strict(),
      )
      .optional(),
    resourcesPath: z.string().optional(),
    aggregate: z.boolean().optional(),
    resourceIdField: z.string().min(1),
    resourceNameField: z.string().optional(),
    applicableWhen: expressionSchema.optional(),
    passWhen: expressionSchema,
    onError: z
      .array(
        z
          .object({
            contains: z.string().min(1),
            status: z.enum(["pass", "fail", "not_applicable", "error"]),
            message: z.string().optional(),
          })
          .strict(),
      )
      .optional(),
    failMessage: z.string().min(1),
    passMessage: z.string().min(1),
    remediation: z
      .object({
        summary: z.string().min(1),
        steps: z.array(z.string()).min(1),
        verifyCommand: z.string().optional(),
      })
      .strict(),
    compliance: z.array(
      z
        .object({
          framework: z.string().min(1),
          version: z.string().optional(),
          controls: z.array(z.string()).min(1),
        })
        .strict(),
    ),
    references: z.array(z.string()),
  })
  .strict();

export type ParsedControl = z.infer<typeof controlSchema>;
export type ParsedCollector = z.infer<typeof collectorSchema>;
