import { describe, expect, it } from "vitest";
import { validateParamValue, validateReadOnlyCommand } from "../src/safety.js";

describe("read-only command validation", () => {
  it("accepts read-only provider commands", () => {
    const commands = [
      "aws s3api list-buckets --output json",
      "aws iam get-account-summary --output json",
      "aws ec2 describe-security-groups --region {region} --output json",
      "az storage account list --output json",
      "az keyvault show --name {resource} --output json",
      "gcloud compute firewall-rules list --project {project} --format json",
      "gcloud sql instances describe {resource} --format json",
      "gsutil iam get gs://{resource}",
    ];
    for (const command of commands) {
      expect(validateReadOnlyCommand(command)).toEqual({ safe: true });
    }
  });

  it("rejects mutating commands", () => {
    const commands = [
      "aws s3api put-public-access-block --bucket b",
      "aws ec2 terminate-instances --instance-ids i-1",
      "aws iam create-user --user-name x",
      "az storage account update --name x --https-only true",
      "az group delete --name x",
      "gcloud compute instances delete x",
      "gcloud projects add-iam-policy-binding p --member m --role r",
      "gsutil rm gs://bucket/object",
      "kubectl get pods",
      "rm -rf /",
    ];
    for (const command of commands) {
      expect(validateReadOnlyCommand(command).safe).toBe(false);
    }
  });

  it("rejects shell metacharacters and injection attempts", () => {
    const commands = [
      "aws s3api list-buckets; rm -rf /",
      "aws s3api list-buckets && aws s3 rb s3://x",
      "aws s3api list-buckets | sh",
      "aws s3api list-buckets $(whoami)",
      "aws s3api list-buckets > /etc/passwd",
      "aws s3api list-buckets `id`",
    ];
    for (const command of commands) {
      expect(validateReadOnlyCommand(command).safe).toBe(false);
    }
  });

  it("validates substitution parameter charset", () => {
    expect(validateParamValue("ap-southeast-2")).toBe(true);
    expect(validateParamValue("my-bucket.example.com")).toBe(true);
    expect(validateParamValue("proj_123:region/us")).toBe(true);
    expect(validateParamValue("a b")).toBe(false);
    expect(validateParamValue("x;rm")).toBe(false);
    expect(validateParamValue("$(id)")).toBe(false);
    expect(validateParamValue("")).toBe(false);
  });
});
