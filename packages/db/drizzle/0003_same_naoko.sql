CREATE TABLE "control_revisions" (
	"control_id" text NOT NULL,
	"version" text NOT NULL,
	"content_hash" text NOT NULL,
	"definition" jsonb NOT NULL,
	"deprecated" boolean DEFAULT false NOT NULL,
	"first_seen_at" timestamp with time zone NOT NULL,
	CONSTRAINT "control_revisions_control_id_version_content_hash_pk" PRIMARY KEY("control_id","version","content_hash")
);
--> statement-breakpoint
CREATE INDEX "idx_control_revisions_control" ON "control_revisions" USING btree ("control_id","first_seen_at");