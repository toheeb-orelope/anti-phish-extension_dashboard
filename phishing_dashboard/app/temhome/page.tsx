// app/page.tsx
"use client";

import { Card, CardHeader, CardBody, CardFooter } from "@heroui/card";
import { Button } from "@heroui/react";

export default function HomePage() {
  return (
    <main className="flex min-h-screen items-center justify-center">
      <Card className="max-w-sm">
        <CardHeader className="font-semibold text-lg">
          HeroUI + Next 16
        </CardHeader>
        <CardBody>
          <p>
            You’re now using the new Tailwind/PostCSS pipeline with HeroUI
            components.
          </p>
        </CardBody>
        <CardFooter>
          <Button color="primary">Get Started</Button>
        </CardFooter>
      </Card>
    </main>
  );
}
