"use client";

import { useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";

interface RefreshIndicatorProps {
  lastUpdated?: Date | string | number;
  autoIntervalSec?: number;
  onRefresh?: () => void;
  isRefreshing?: boolean;
  className?: string;
}

export function RefreshIndicator({
  lastUpdated,
  autoIntervalSec,
  onRefresh,
  isRefreshing = false,
  className = "",
}: RefreshIndicatorProps) {
  const [, setTick] = useState(0);

  // Re-render every 5 seconds to update "X lalu"
  useEffect(() => {
    const timer = setInterval(() => setTick((t) => t + 1), 5000);
    return () => clearInterval(timer);
  }, []);

  const getRelativeText = () => {
    if (!lastUpdated) return "baru saja";
    const d = new Date(lastUpdated);
    if (isNaN(d.getTime())) return "baru saja";
    const diffSec = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
    if (diffSec < 5) return "baru saja";
    if (diffSec < 60) return `${diffSec}d lalu`;
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m lalu`;
    return `${Math.floor(diffSec / 3600)}j lalu`;
  };

  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <span className="text-[11px] font-mono text-muted-foreground whitespace-nowrap">
        Diperbarui {getRelativeText()}
        {autoIntervalSec ? ` • auto ${autoIntervalSec}d` : ""}
      </span>
      {onRefresh && (
        <Button
          variant="outline"
          size="sm"
          className="h-7 px-2 text-xs gap-1 text-muted-foreground hover:text-foreground"
          onClick={onRefresh}
          disabled={isRefreshing}
          title="Segarkan data sekarang"
        >
          <RefreshCw className={`size-3 ${isRefreshing ? "animate-spin" : ""}`} />
          Segarkan
        </Button>
      )}
    </div>
  );
}
