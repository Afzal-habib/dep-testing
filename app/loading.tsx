import { ProfessionalLoader } from "@/components/shared/professional-loader";

export default function Loading() {
  return (
    <div className="fixed inset-0 bg-background flex items-center justify-center z-50">
      <ProfessionalLoader
        size="md"
      />
    </div>
  )
}