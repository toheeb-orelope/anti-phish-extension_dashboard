import { Card, CardBody, CardHeader } from "@heroui/card";
import ScanBox from "@/componets/scan_box";

export default function Home() {
  return (
    <main className="mx-auto max-w-4xl">
      <div className="mb-6">
        <h1 className="text-3xl font-semibold">Scan a URL</h1>
        <p className="text-default-500">Checks both cloud tools and local heuristics.</p>
      </div>
      <Card>
        <CardHeader className="font-medium">Quick Scan</CardHeader>
        <CardBody>
          <ScanBox />
        </CardBody>
      </Card>
    </main>
  );
}
