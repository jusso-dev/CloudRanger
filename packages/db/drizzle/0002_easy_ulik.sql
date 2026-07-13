CREATE TABLE "scope_parameters" (
	"provider" varchar(16) NOT NULL,
	"scope_id" text NOT NULL,
	"control_id" text NOT NULL,
	"parameters" jsonb NOT NULL,
	"updated_at" timestamp with time zone NOT NULL,
	CONSTRAINT "scope_parameters_provider_scope_id_control_id_pk" PRIMARY KEY("provider","scope_id","control_id")
);
--> statement-breakpoint
ALTER TABLE "evaluations" ADD COLUMN "effective_parameters" jsonb;--> statement-breakpoint
ALTER TABLE "findings" ADD COLUMN "effective_parameters" jsonb;--> statement-breakpoint
ALTER TABLE "scans" ADD COLUMN "parameters" jsonb;