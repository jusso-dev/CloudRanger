CREATE TABLE "identities" (
	"subject" text PRIMARY KEY NOT NULL,
	"display_name" text,
	"created_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "workspace_memberships" (
	"workspace_id" varchar(63) NOT NULL,
	"subject" text NOT NULL,
	"role" varchar(16) NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"updated_at" timestamp with time zone NOT NULL,
	CONSTRAINT "workspace_memberships_workspace_id_subject_pk" PRIMARY KEY("workspace_id","subject")
);
--> statement-breakpoint
CREATE TABLE "workspaces" (
	"id" varchar(63) PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"created_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "workspace_memberships" ADD CONSTRAINT "workspace_memberships_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "workspace_memberships" ADD CONSTRAINT "workspace_memberships_subject_identities_subject_fk" FOREIGN KEY ("subject") REFERENCES "public"."identities"("subject") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_workspace_memberships_subject" ON "workspace_memberships" USING btree ("subject");