"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { ProfessionalLoader } from "./professional-loader";

export function RouteLoader() {
  const [isLoading, setIsLoading] = useState(false);
  const pathname = usePathname();

  useEffect(() => {
    // Only show loader for slower operations
    setIsLoading(true);

    // Much faster loading timeout
    const timeout = setTimeout(() => setIsLoading(false), 150);

    return () => {
      clearTimeout(timeout);
    };
  }, [pathname]);

  if (!isLoading) return null;

  return (
    <div className="fixed inset-0 bg-background flex items-center justify-center z-50">
      <ProfessionalLoader
        size="md"
      />
    </div>
  );
}