"use client";

interface TimestampProps {
  time: string | number | Date | undefined | null;
  relative?: boolean;
  className?: string;
  showDate?: boolean;
}

export function formatWibDateTime(dateInput: string | number | Date): string {
  const d = new Date(dateInput);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleString("id-ID", {
    timeZone: "Asia/Jakarta",
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

export function formatRelativeTime(dateInput: string | number | Date): string {
  const d = new Date(dateInput);
  if (isNaN(d.getTime())) return "—";
  const diffSec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (diffSec < 0) return "baru saja";
  if (diffSec < 60) return `${diffSec}d lalu`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m lalu`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}j lalu`;
  return d.toLocaleDateString("id-ID", {
    timeZone: "Asia/Jakarta",
    day: "2-digit",
    month: "short",
  });
}

export function Timestamp({
  time,
  relative = false,
  className = "",
  showDate = true,
}: TimestampProps) {
  if (!time) {
    return <span className={`text-muted-foreground font-mono text-xs tabular-nums ${className}`}>—</span>;
  }

  const d = new Date(time);
  if (isNaN(d.getTime())) {
    return <span className={`text-muted-foreground font-mono text-xs tabular-nums ${className}`}>—</span>;
  }

  const isoUtc = d.toISOString();
  const diffSec = Math.abs((Date.now() - d.getTime()) / 1000);
  const isRecent = diffSec < 86400; // < 24 hours

  const timeStr = d.toLocaleTimeString("id-ID", {
    timeZone: "Asia/Jakarta",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });

  const dateStr = d.toLocaleDateString("id-ID", {
    timeZone: "Asia/Jakarta",
    day: "2-digit",
    month: "short",
  });

  return (
    <span
      className={`font-mono tabular-nums whitespace-nowrap text-xs cursor-default ${className}`}
      title={`${isoUtc} (UTC)`}
    >
      {relative && isRecent ? (
        <span className="flex items-center gap-1.5">
          <span>{formatRelativeTime(d)}</span>
          <span className="text-[10px] text-muted-foreground">({timeStr})</span>
        </span>
      ) : showDate ? (
        <span className="flex items-center gap-1.5">
          <span className="text-muted-foreground text-[11px]">{dateStr}</span>
          <span>{timeStr}</span>
        </span>
      ) : (
        <span>{timeStr}</span>
      )}
    </span>
  );
}
