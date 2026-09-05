import { randomUUID, } from "node:crypto";
const scans = [];
/*
 * ---------------------------------------
 * SAVE SCAN
 * ---------------------------------------
 */
export function saveScan(type, content, result, event) {
    const scan = {
        id: randomUUID(),
        type,
        content,
        result,
        event,
        createdAt: new Date().toISOString(),
    };
    scans.unshift(scan);
    return scan;
}
/*
 * ---------------------------------------
 * GET SCANS
 * ---------------------------------------
 */
export function getScans(limit = 10) {
    const safeLimit = Math.max(1, Math.min(limit, 100));
    return scans.slice(0, safeLimit);
}
/*
 * ---------------------------------------
 * CLEAR SCANS
 * ---------------------------------------
 */
export function clearScans() {
    scans.length = 0;
}
/*
 * ---------------------------------------
 * GET DASHBOARD STATS
 * ---------------------------------------
 */
export function getScanStats() {
    const totalScans = scans.length;
    const highRisk = scans.filter((scan) => scan.result
        .riskLevel ===
        "High").length;
    const mediumRisk = scans.filter((scan) => scan.result
        .riskLevel ===
        "Medium").length;
    const lowRisk = scans.filter((scan) => scan.result
        .riskLevel ===
        "Low").length;
    return {
        totalScans,
        highRisk,
        mediumRisk,
        lowRisk,
    };
}
//# sourceMappingURL=scanService.js.map