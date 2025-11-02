"use client";

import { Card, CardHeader, CardBody } from "@heroui/card";
import { Link } from "@heroui/react";

export default function AboutContent() {
  return (
    <Card>
      <CardHeader>
        <h1 className="text-2xl font-semibold">About</h1>
      </CardHeader>
      <CardBody className="space-y-4">
        <p>
          This dashboard works with the Anti‑Phishing browser extension. The
          extension scans URLs in the background using a combination of cloud
          reputation services and local heuristics. If a page is risky, access
          is blocked and you get a red alert with reasons and a link to open
          this dashboard for more details.
        </p>
        <p>
          You can also paste a URL on the Home page to scan on‑demand. The
          Charts section summarizes provider ratings.
        </p>
        <p className="text-default-500 text-sm">
          Note: In this preview, provider calls can be mocked or live. Configure
          your keys in <code className="font-mono">.env.local</code>.
        </p>
        <p>
          Need help? Visit the project README or contact support. <Link href="/" color="primary">Back to Home</Link>
        </p>
      </CardBody>
    </Card>
  );
}

