"use client";

import { useNavigation } from "@/components/providers/navigation-provider";

export function useNavigationLoading() {
  const { navigateTo, isNavigating } = useNavigation()

  return {
    isNavigating,
    handleNavigation: navigateTo,
  };
}