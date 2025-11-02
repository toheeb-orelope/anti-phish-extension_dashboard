import { NextRequest, NextResponse } from "next/server";

type ProviderFinding = {
  provider: "virusTools" | "localRun";
  riskScore: number; // 0-100
  verdict: "clean" | "suspicious" | "malicious";
  reasons: string[];
  meta?: Record<string, unknown>;
};

type ScanResult = {
  url: string;
  overallVerdict: "clean" | "suspicious" | "malicious";
  blockRecommended: boolean;
  findings: ProviderFinding[];
  scannedAt: string;
};

function normalizeVerdict(v?: string): "clean" | "suspicious" | "malicious" {
  const s = (v || "").toLowerCase();
  if (/malic/.test(s) || /phish/.test(s)) return "malicious";
  if (/suspici/.test(s) || /unknown|grey|gray/.test(s)) return "suspicious";
  return "clean";
}

// Accept precomputed results passed by the extension
function fromExtensionPayload(url: string, body: any): ProviderFinding[] | null {
  const findings: ProviderFinding[] = [];
  let haveAny = false;
  if (body?.vt) {
    haveAny = true;
    const stats = body.vt.stats || {};
    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const harmless = Number(stats.harmless || 0);
    const undetected = Number(stats.undetected || 0);
    const total = Math.max(1, malicious + suspicious + harmless + undetected);
    const riskScore = Math.min(
      100,
      Math.round(((malicious * 3 + suspicious * 2) / (total * 3)) * 100)
    );
    const verdict = normalizeVerdict(body.vt.verdict);
    findings.push({
      provider: "virusTools",
      riskScore,
      verdict,
      reasons: [
        `Malicious: ${malicious}`,
        `Suspicious: ${suspicious}`,
        `Harmless: ${harmless}`,
        `Undetected: ${undetected}`,
      ],
      meta: { analysisId: body.vt.analysisId ?? null },
    });
  }
  if (body?.local) {
    haveAny = true;
    const verdict = normalizeVerdict(body.local.verdict);
    const reasons: string[] = Array.isArray(body.local.reasons)
      ? body.local.reasons
      : [];
    const riskScore = verdict === "malicious" ? 75 : verdict === "suspicious" ? 50 : 5;
    findings.push({ provider: "localRun", riskScore, verdict, reasons, meta: {} });
  }
  return haveAny ? findings : null;
}

// Real provider calls (server-side)
async function vtScanUrl(url: string, apiKey?: string) {
  if (!apiKey) return { ok: false, error: "Missing VirusTotal API key" } as const;
  try {
    const form = new URLSearchParams();
    form.set("url", url);
    const submit = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": apiKey,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: form.toString(),
    });
    const submitJson: any = await submit.json();
    const analysisId = submitJson?.data?.id;
    if (!analysisId) return { ok: false, error: "No analysis ID" } as const;

    let analysis: any = null;
    for (let i = 0; i < 6; i++) {
      const res = await fetch(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        {
          headers: { "x-apikey": apiKey },
        }
      );
      const j: any = await res.json();
      const status = j?.data?.attributes?.status;
      if (status === "completed") {
        analysis = j;
        break;
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
    if (!analysis) return { ok: false, error: "Analysis not ready" } as const;

    const stats =
      analysis?.data?.attributes?.stats ||
      analysis?.data?.attributes?.results ||
      analysis?.data?.attributes?.last_analysis_stats ||
      {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    const verdict = malicious > 0 || suspicious > 0 ? "malicious" : "clean";
    return { ok: true as const, verdict, stats, analysisId, raw: analysis };
  } catch (e: any) {
    return { ok: false as const, error: String(e?.message || e) };
  }
}

async function localPredict(url: string, apiKey?: string) {
  try {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (apiKey) headers["X-API-Key"] = apiKey;
    const res = await fetch("http://127.0.0.1:8000/predict", {
      method: "POST",
      headers,
      body: JSON.stringify({ url, user_id: "browser-extension" }),
    });
    const json: any = await res.json();
    const verdict = /phish/i.test(json?.verdict || "")
      ? "malicious"
      : /benign|harmless|clean/i.test(json?.verdict || "")
      ? "clean"
      : "suspicious";
    const reasons: string[] = Array.isArray(json?.reasons) ? json.reasons : [];
    return { ok: true as const, verdict, raw: json, reasons };
  } catch (e: any) {
    return { ok: false as const, error: String(e?.message || e) };
  }
}

// Simple heuristic mocks (replace with real provider calls later)
function mockVirusTools(url: string): ProviderFinding {
  const lowered = url.toLowerCase();
  let risk = 5;
  const reasons: string[] = [];
  if (/[\"'<>]/.test(url)) {
    risk += 30;
    reasons.push("URL contains potentially dangerous characters");
  }
  if (/(free|win|gift|login|verify|bank)/.test(lowered)) {
    risk += 25;
    reasons.push("Contains common phishing bait keywords");
  }
  if (/\.ru|\.cn|\.tk|\.top|\.xyz/.test(lowered)) {
    risk += 15;
    reasons.push("Suspicious TLD detected");
  }
  if (/ipfs|onion/.test(lowered)) {
    risk += 15;
    reasons.push("Decentralized/hidden hosting marker");
  }
  const riskScore = Math.min(100, risk);
  const verdict =
    riskScore >= 70 ? "malicious" : riskScore >= 35 ? "suspicious" : "clean";
  return { provider: "virusTools", riskScore, verdict, reasons };
}

function mockLocalRun(url: string): ProviderFinding {
  const lowered = url.toLowerCase();
  let risk = 0;
  const reasons: string[] = [];
  try {
    const u = new URL(/^https?:\/\//i.test(url) ? url : `https://${url}`);
    const host = u.hostname;
    const path = u.pathname || "/";
    if (/\d{1,3}(?:\.\d{1,3}){3}/.test(host)) {
      risk += 30;
      reasons.push("Bare IPv4 address in host");
    }
    if (host.split(".").length > 4) {
      risk += 15;
      reasons.push("Excessive subdomain depth");
    }
    if (/@/.test(url)) {
      risk += 20;
      reasons.push("@ symbol in URL path");
    }
    if (/\.(zip|exe|scr)(?:$|[?&#])/.test(lowered)) {
      risk += 25;
      reasons.push("Executable/archive extension in URL");
    }
    if (/\/(login|verify|update|secure|wallet)/.test(path)) {
      risk += 20;
      reasons.push("Sensitive action path detected");
    }
  } catch {
    risk += 40;
    reasons.push("Invalid URL format");
  }
  const riskScore = Math.min(100, Math.max(5, risk));
  const verdict =
    riskScore >= 70 ? "malicious" : riskScore >= 35 ? "suspicious" : "clean";
  return { provider: "localRun", riskScore, verdict, reasons };
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const url = (body?.url as string | undefined)?.trim();
    if (!url) {
      return NextResponse.json(
        { error: "Missing 'url' in request body" },
        { status: 400 }
      );
    }

    // Use extension payload when provided
    let findings = fromExtensionPayload(url, body);

    if (!findings) {
      // Try real providers when keys exist, otherwise fall back to mocks
      const vtKey = process.env.VIRUSTOTAL_API_KEY || process.env.VIRUSTOOLS_API_KEY;
      const localKey = process.env.LOCAL_API_KEY;

      if (vtKey) {
        const vt = await vtScanUrl(url, vtKey);
        if (vt.ok) {
          const stats: any = vt.stats || {};
          const malicious = Number(stats.malicious || 0);
          const suspicious = Number(stats.suspicious || 0);
          const harmless = Number(stats.harmless || 0);
          const undetected = Number(stats.undetected || 0);
          const total = Math.max(1, malicious + suspicious + harmless + undetected);
          const vtRisk = Math.min(100, Math.round(((malicious * 3 + suspicious * 2) / (total * 3)) * 100));
          findings = [
            {
              provider: "virusTools",
              riskScore: vtRisk,
              verdict: normalizeVerdict(vt.verdict),
              reasons: [
                `Malicious: ${malicious}`,
                `Suspicious: ${suspicious}`,
                `Harmless: ${harmless}`,
                `Undetected: ${undetected}`,
              ],
              meta: { analysisId: vt.analysisId ?? null },
            },
          ];
        } else {
          findings = [mockVirusTools(url)];
        }
      } else {
        findings = [mockVirusTools(url)];
      }

      const local = await localPredict(url, localKey);
      if (local.ok) {
        findings.push({
          provider: "localRun",
          riskScore: local.verdict === "malicious" ? 75 : local.verdict === "suspicious" ? 50 : 5,
          verdict: local.verdict,
          reasons: local.reasons || [],
          meta: {},
        });
      } else {
        findings.push(mockLocalRun(url));
      }
    }

    const worst = findings.reduce((a, b) => (a.riskScore >= b.riskScore ? a : b));
    const overallVerdict = worst.verdict;
    const blockRecommended = overallVerdict !== "clean";

    const result: ScanResult = {
      url,
      overallVerdict,
      blockRecommended,
      findings: findings,
      scannedAt: new Date().toISOString(),
    };
    return NextResponse.json(result);
  } catch (e) {
    return NextResponse.json(
      { error: "Unexpected error", details: String(e) },
      { status: 500 }
    );
  }
}
