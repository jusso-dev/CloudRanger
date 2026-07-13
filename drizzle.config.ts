import { defineConfig } from "drizzle-kit";

export default defineConfig({
  schema: "./src/drizzle-schema.ts",
  out: "./drizzle",
  dialect: "postgresql",
  dbCredentials: {
    url: process.env.CLOUDRANGER_DATABASE_URL ?? "postgresql://localhost/cloudranger",
  },
});
