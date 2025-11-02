import ChartsView from "@/componets/charts_view";

export default function ChartsPage() {
  return (
    <main className="mx-auto max-w-5xl">
      <div className="mb-6">
        <h1 className="text-2xl font-semibold">Provider Ratings</h1>
        <p className="text-default-500">A quick glance at risk and outcomes.</p>
      </div>
      <ChartsView />
    </main>
  );
}
