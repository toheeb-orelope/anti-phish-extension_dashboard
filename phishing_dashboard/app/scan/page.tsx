import ScanDetails from "@/componets/scan_details";

export default function Page({
  searchParams,
}: {
  searchParams: { url?: string; vt?: string; local?: string };
}) {
  const url = searchParams?.url || "";
  const vt = searchParams?.vt;
  const local = searchParams?.local;
  return (
    <main className="mx-auto max-w-4xl">
      <ScanDetails initialUrl={url} vtParam={vt} localParam={local} />
    </main>
  );
}
