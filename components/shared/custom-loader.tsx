import { ProfessionalLoader } from "./professional-loader";

export default function CustomLoader({ show = true }: { show?: boolean }) {
    return (
        show ? (
            <div className="fixed inset-0 bg-background flex items-center justify-center z-50">
                <ProfessionalLoader
                    size="md"
                />
            </div>
        ) : null
    );
}