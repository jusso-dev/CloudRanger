CREATE TABLE "imported_signals" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "imported_signals_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"provider" varchar(16) NOT NULL,
	"scope_id" text NOT NULL,
	"source" varchar(16) NOT NULL,
	"external_id" text NOT NULL,
	"title" text NOT NULL,
	"severity" text NOT NULL,
	"resource_id" text NOT NULL,
	"description" text,
	"correlated_fingerprints" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"imported_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX "uq_imported_signals" ON "imported_signals" USING btree ("provider","scope_id","source","external_id");--> statement-breakpoint
CREATE INDEX "idx_imported_signals_scope" ON "imported_signals" USING btree ("provider","scope_id","source");