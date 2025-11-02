"use client";

import { useMemo } from "react";
import { Card, CardHeader, CardBody } from "@heroui/card";
import { CircularProgress, Divider } from "@heroui/react";

type Rating = {
  provider: string;
  avgRisk: number; // 0-100
  totalScans: number;
  maliciousPct: number; // 0-100
  suspiciousPct: number; // 0-100
};

export default function ChartsView() {
  const data: Rating[] = useMemo(
    () => [
      { provider: "virusTools", avgRisk: 48, totalScans: 1240, maliciousPct: 18, suspiciousPct: 26 },
      { provider: "localRun", avgRisk: 34, totalScans: 1240, maliciousPct: 12, suspiciousPct: 22 },
    ],
    []
  );

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {data.map((r) => (
        <Card key={r.provider} className="border border-default-100">
          <CardHeader className="flex items-center justify-between">
            <div className="font-semibold capitalize">{r.provider}</div>
            <div className="text-sm text-default-500">{r.totalScans.toLocaleString()} scans</div>
          </CardHeader>
          <CardBody>
            <div className="flex gap-6 items-center">
              <div className="flex items-center gap-3">
                <CircularProgress
                  aria-label="Average risk"
                  value={r.avgRisk}
                  showValueLabel
                  color={r.avgRisk >= 70 ? "danger" : r.avgRisk >= 35 ? "warning" : "success"}
                />
                <div>
                  <div className="text-sm text-default-500">Average risk</div>
                  <div className="text-default-700">{r.avgRisk}%</div>
                </div>
              </div>
              <Divider orientation="vertical" className="h-16" />
              <div className="grid grid-cols-2 gap-6 text-sm">
                <div>
                  <div className="text-default-500">Malicious</div>
                  <div className="font-medium">{r.maliciousPct}%</div>
                </div>
                <div>
                  <div className="text-default-500">Suspicious</div>
                  <div className="font-medium">{r.suspiciousPct}%</div>
                </div>
              </div>
            </div>
          </CardBody>
        </Card>
      ))}
    </div>
  );
}

