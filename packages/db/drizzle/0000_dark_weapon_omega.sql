CREATE TABLE "audit_log" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "audit_log_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"created_at" timestamp with time zone NOT NULL,
	"actor" text NOT NULL,
	"tool" text NOT NULL,
	"args" jsonb,
	"success" boolean NOT NULL,
	"detail" text,
	"prev_hash" text NOT NULL,
	"entry_hash" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "evaluations" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "evaluations_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"scan_id" varchar(36) NOT NULL,
	"control_id" text NOT NULL,
	"control_version" text NOT NULL,
	"status" text NOT NULL,
	"severity" text NOT NULL,
	"service" text NOT NULL,
	"resource_id" text NOT NULL,
	"resource_name" text,
	"region" text,
	"message" text NOT NULL,
	"evidence" jsonb,
	"evaluated_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "evidence" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "evidence_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"scan_id" varchar(36) NOT NULL,
	"collector_id" text NOT NULL,
	"region" text,
	"resource_key" text,
	"output" jsonb,
	"error_text" text,
	"exit_code" integer NOT NULL,
	"evidence_hash" text NOT NULL,
	"collected_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "finding_events" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "finding_events_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"fingerprint" text NOT NULL,
	"scan_id" varchar(36),
	"event_type" text NOT NULL,
	"from_state" text,
	"to_state" text,
	"message" text,
	"evidence" jsonb,
	"actor" text,
	"created_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "findings" (
	"fingerprint" text PRIMARY KEY NOT NULL,
	"provider" text NOT NULL,
	"scope_id" text NOT NULL,
	"control_id" text NOT NULL,
	"control_version" text NOT NULL,
	"severity" text NOT NULL,
	"service" text NOT NULL,
	"resource_id" text NOT NULL,
	"resource_name" text,
	"region" text,
	"state" text DEFAULT 'open' NOT NULL,
	"workflow_state" text DEFAULT 'new' NOT NULL,
	"workflow_reason" text,
	"workflow_actor" text,
	"workflow_expires_at" timestamp with time zone,
	"owner" text,
	"due_at" timestamp with time zone,
	"message" text NOT NULL,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL,
	"resolved_at" timestamp with time zone,
	"occurrence_count" integer DEFAULT 1 NOT NULL,
	"reopen_count" integer DEFAULT 0 NOT NULL,
	"last_scan_id" varchar(36) NOT NULL,
	"latest_evidence" jsonb
);
--> statement-breakpoint
CREATE TABLE "scans" (
	"id" varchar(36) PRIMARY KEY NOT NULL,
	"provider" varchar(16) NOT NULL,
	"scope_id" text NOT NULL,
	"regions" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"control_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"status" varchar(16) DEFAULT 'collecting' NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"evaluated_at" timestamp with time zone,
	"coverage" jsonb,
	"summary" jsonb
);
--> statement-breakpoint
CREATE INDEX "idx_evidence_scan" ON "evidence" USING btree ("scan_id","collector_id");--> statement-breakpoint
CREATE INDEX "idx_findings_state" ON "findings" USING btree ("state","severity");--> statement-breakpoint
CREATE INDEX "idx_findings_scope" ON "findings" USING btree ("provider","scope_id");--> statement-breakpoint
CREATE INDEX "idx_findings_control" ON "findings" USING btree ("control_id");--> statement-breakpoint
CREATE INDEX "idx_findings_owner_due" ON "findings" USING btree ("owner","due_at");