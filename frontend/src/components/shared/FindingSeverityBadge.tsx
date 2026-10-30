// ─── src/components/shared/FindingSeverityBadge.tsx ───────────────
const styles: Record<string, string> = {
  critical: "bg-red-100 text-red-700",
  high: "bg-orange-100 text-orange-700",
  medium: "bg-amber-100 text-amber-700",
  low: "bg-blue-100 text-blue-700",
  info: "bg-gray-100 text-gray-600",
};

export default function FindingSeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full font-medium flex-shrink-0 capitalize ${styles[severity] || styles.info}`}>
      {severity}
    </span>
  );
}
