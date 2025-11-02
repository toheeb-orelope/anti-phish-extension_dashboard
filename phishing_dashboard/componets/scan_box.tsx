// To contain scan/search box component of the web application

"use client";

import { useCallback, useMemo, useState } from "react";
import { Button, Input, Link, Chip, Snippet, Spinner } from "@heroui/react";

export const SearchIcon = (props: React.SVGProps<SVGSVGElement>) => {
  return (
    <svg
      aria-hidden="true"
      fill="none"
      focusable="false"
      height="1em"
      role="presentation"
      viewBox="0 0 24 24"
      width="1em"
      {...props}
    >
      <path
        d="M11.5 21C16.7467 21 21 16.7467 21 11.5C21 6.25329 16.7467 2 11.5 2C6.25329 2 2 6.25329 2 11.5C2 16.7467 6.25329 21 11.5 21Z"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="2"
      />
      <path
        d="M22 22L20 20"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="2"
      />
    </svg>
  );
};

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

export default function ScanBox() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);

  const canScan = useMemo(() => url.trim().length > 3 && !loading, [url, loading]);

  const onScan = useCallback(async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error || "Scan failed");
      setResult(data as ScanResult);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setLoading(false);
    }
  }, [url]);

  return (
    <div className="w-full max-w-2xl rounded-2xl p-6 bg-default-100/50 border border-default-200">
      <div className="flex flex-col gap-4">
        <div className="flex gap-2 items-center">
          <Input
            isClearable
            value={url}
            onValueChange={setUrl}
            classNames={{
              input: [
                "bg-transparent",
                "placeholder:text-default-700/50 dark:placeholder:text-white/60",
              ],
            }}
            placeholder="Paste or type a URL to scan (e.g., https://example.com)"
            radius="lg"
            startContent={
              <SearchIcon className="text-default-500 mb-0.5 text-slate-400 pointer-events-none shrink-0" />
            }
          />
          <Button color="primary" isDisabled={!canScan} isLoading={loading} onPress={onScan}>
            Scan
          </Button>
        </div>

        {loading && (
          <div className="flex items-center gap-2 text-default-600">
            <Spinner size="sm" />
            <span>Scanning…</span>
          </div>
        )}
        {error && (
          <Chip color="danger" variant="flat">
            {error}
          </Chip>
        )}

        {result && (
          <div
            className={
              "flex flex-col gap-2 border rounded-medium p-3 " +
              (result.overallVerdict === "malicious"
                ? "border-danger-300 bg-danger-50/40"
                : result.overallVerdict === "suspicious"
                ? "border-warning-300 bg-warning-50/40"
                : "border-success-300 bg-success-50/40")
            }
          >
            <div className="flex items-center gap-2">
              <Chip
                color={result.overallVerdict === "malicious" ? "danger" : result.overallVerdict === "suspicious" ? "warning" : "success"}
                variant="flat"
                className="capitalize"
              >
                {result.overallVerdict}
              </Chip>
              <Chip color={result.blockRecommended ? "danger" : "success"} variant="flat">
                {result.blockRecommended ? "Block recommended" : "No block"}
              </Chip>
            </div>
            <Snippet hideSymbol>{result.url}</Snippet>
            <div>
              <Button
                as={Link}
                href={`/scan?url=${encodeURIComponent(result.url)}`}
                color="secondary"
                variant="flat"
              >
                Open Dashboard
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
