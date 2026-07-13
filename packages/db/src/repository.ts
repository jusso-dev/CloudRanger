import type {
  ControlCoverage,
  EvaluationResult,
  EvidenceRecord,
  Provider,
  WorkflowState,
} from "@cloudranger/engine";
import type {
  FindingEventRow,
  FindingRow,
  FindingSearchFilters,
  ScanComparison,
  ScanHealth,
  ScanRow,
  ScanSummary,
} from "./index.js";

/** Async persistence contract used by networked and local backends. */
export interface CloudRangerRepository {
  close(): Promise<void>;
  createScan(input: {
    provider: Provider;
    scopeId: string;
    regions: string[];
    controlIds: string[];
  }): Promise<ScanRow>;
  getScan(id: string): Promise<ScanRow | undefined>;
  listScans(limit?: number): Promise<ScanRow[]>;
  compareScans(baselineScanId: string, currentScanId: string): Promise<ScanComparison>;
  cancelScan(id: string): Promise<void>;
  addEvidence(scanId: string, records: Omit<EvidenceRecord, "collectedAt">[]): Promise<number>;
  getEvidence(scanId: string): Promise<EvidenceRecord[]>;
  evidenceStats(
    scanId: string,
  ): Promise<Array<{ collectorId: string; region?: string; records: number; errors: number }>>;
  scanHealth(
    scanId: string,
    staleAfterMinutes?: number,
    expectedCollectorIds?: string[],
  ): Promise<ScanHealth>;
  finalizeScan(
    scanId: string,
    results: EvaluationResult[],
    coverage: ControlCoverage[],
  ): Promise<ScanSummary>;
  searchFindings(
    filters?: FindingSearchFilters,
  ): Promise<{ total: number; findings: FindingRow[] }>;
  getFinding(fingerprint: string): Promise<FindingRow | undefined>;
  getFindingEvents(fingerprint: string): Promise<FindingEventRow[]>;
  setWorkflowState(
    fingerprint: string,
    workflowState: WorkflowState,
    opts: { reason?: string; actor: string; expiresAt?: string },
  ): Promise<FindingRow>;
  assignFinding(
    fingerprint: string,
    opts: { owner: string; dueAt?: string; actor: string },
  ): Promise<FindingRow>;
  expireWorkflowStates(now?: string): Promise<number>;
  addFindingComment(fingerprint: string, comment: string, actor: string): Promise<void>;
  reportData(filters?: {
    provider?: Provider;
    scopeId?: string;
    sinceDays?: number;
  }): Promise<unknown>;
  audit(entry: {
    actor: string;
    tool: string;
    args?: unknown;
    success: boolean;
    detail?: string;
  }): Promise<void>;
  searchAudit(limit?: number): Promise<unknown[]>;
  verifyAuditChain(): Promise<number | null>;
}
