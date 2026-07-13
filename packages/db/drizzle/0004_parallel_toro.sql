CREATE TABLE "retention_policies" (
	"provider" varchar(16) NOT NULL,
	"scope_id" text NOT NULL,
	"keep_days" integer,
	"keep_scans" integer,
	"updated_at" timestamp with time zone NOT NULL,
	CONSTRAINT "retention_policies_provider_scope_id_pk" PRIMARY KEY("provider","scope_id")
);
--> statement-breakpoint
ALTER TABLE "evidence" ADD COLUMN "pruned_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "evidence" ADD COLUMN "output_bytes" integer;