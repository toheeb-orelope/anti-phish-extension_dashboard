"use client";

import { useEffect, useMemo, useState } from "react";
import { Card, CardHeader, CardBody, CardFooter } from "@heroui/card";
import { Button, Chip, Divider, Link, Snippet, Progress, CircularProgress } from "@heroui/react";

type ProviderFinding = {
  provider: "virusTools" | "localRun";
  riskScore: number;
  verdict: "clean" | "suspicious" | "malicious";
  reasons: string[];
};

type ScanResult = {
  url: string;
  overallVerdict: "clean" | "suspicious" | "malicious";
  blockRecommended: boolean;
  findings: ProviderFinding[];
  scannedAt: string;
};

function parsePayload(param?: string | null): any | undefined {
  if (!param) return undefined;
  try {
    return JSON.parse(param);
  } catch {}
  try {
    // base64-encoded JSON
    return JSON.parse(atob(param));
  } catch {}
  return undefined;
}

export default function ScanDetails({
  initialUrl,
  vtParam,
  localParam,
}: {
  initialUrl?: string;
  vtParam?: string;
  localParam?: string;
}) {
  const [url, setUrl] = useState(initialUrl || "");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<ScanResult | null>(null);
  const [vtPayload] = useState<any | undefined>(() => parsePayload(vtParam));
  const [localPayload] = useState<any | undefined>(() => parsePayload(localParam));

  const verdictColor = useMemo(() => {
    const v = data?.overallVerdict;
    if (v === "malicious") return "danger" as const;
    if (v === "suspicious") return "warning" as const;
    return "success" as const;
  }, [data?.overallVerdict]);

  useEffect(() => {
    let effectiveUrl = url;
    if (!effectiveUrl && typeof window !== "undefined") {
      try {
        const sp = new URLSearchParams(window.location.search);
        effectiveUrl = sp.get("url") || "";
        if (effectiveUrl) setUrl(effectiveUrl);
      } catch {}
    }
    if (!effectiveUrl) return;
    setLoading(true);
    setError(null);
    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: effectiveUrl, vt: vtPayload, local: localPayload }),
    })
      .then(async (r) => {
        if (!r.ok) throw new Error((await r.json()).error || "Scan failed");
        return r.json();
      })
      .then((j: ScanResult) => setData(j))
      .catch((e) => setError(String(e.message || e)))
      .finally(() => setLoading(false));
  }, [url, vtPayload, localPayload]);

  return (
    <Card>
      <CardHeader className="flex flex-col gap-2">
        <h1 className="text-2xl font-semibold">Scan Details</h1>
        <Snippet hideCopyButton={false} hideSymbol variant="flat">
          {url || "No URL provided"}
        </Snippet>
      </CardHeader>
      <Divider />
      <CardBody className="flex flex-col gap-6">
        {loading && <Progress size="sm" isIndeterminate aria-label="Scanning" />}
        {error && (
          <Chip color="danger" variant="flat">
            {error}
          </Chip>
        )}
        {data && (
          <div className="flex flex-col gap-6">
            <div className="flex items-center gap-4">
              <CircularProgress
                aria-label="Overall risk"
                value={
                  Math.round(
                    Math.max(...data.findings.map((f) => f.riskScore)) || 0
                  )
                }
                color={verdictColor}
                showValueLabel
              />
              <div className="flex flex-col">
                <div className="text-sm text-default-500">Overall verdict</div>
                <div className="text-xl font-medium capitalize">
                  {data.overallVerdict}
                </div>
                <Chip
                  className="mt-2 self-start"
                  color={data.blockRecommended ? "danger" : "success"}
                  variant="flat"
                >
                  {data.blockRecommended ? "Block recommended" : "No block"}
                </Chip>
              </div>
            </div>

            <Divider />

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {data.findings.map((f) => (
                <Card key={f.provider} className="border border-default-100">
                  <CardHeader className="flex items-center justify-between">
                    <div className="font-semibold">{f.provider}</div>
                    <Chip
                      color={
                        f.verdict === "malicious"
                          ? "danger"
                          : f.verdict === "suspicious"
                          ? "warning"
                          : "success"
                      }
                      variant="flat"
                    >
                      {f.verdict}
                    </Chip>
                  </CardHeader>
                  <CardBody className="flex flex-col gap-3">
                    <Progress
                      aria-label="Risk score"
                      value={Math.round(f.riskScore)}
                      color={
                        f.riskScore >= 70
                          ? "danger"
                          : f.riskScore >= 35
                          ? "warning"
                          : "success"
                      }
                      showValueLabel
                    />
                    <div className="flex flex-col gap-1 text-sm text-default-600">
                      {f.reasons.length === 0 && <span>No reasons reported.</span>}
                      {f.reasons.map((r, i) => (
                        <span key={i}>• {r}</span>
                      ))}
                    </div>
                  </CardBody>
                </Card>
              ))}
            </div>
          </div>
        )}
      </CardBody>
      <Divider />
      <CardFooter className="flex justify-between">
        <Button as={Link} href="/" color="primary" variant="flat">
          New Scan
        </Button>
        <div className="text-xs text-default-500">
          {data?.scannedAt ? `Scanned at ${new Date(data.scannedAt).toLocaleString()}` : ""}
        </div>
      </CardFooter>
    </Card>
  );
}
