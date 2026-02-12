import type { QuizStats } from '@/lib/types/quiz';

interface QuickStatsProps {
  stats: QuizStats;
}

/** SVG circular progress ring */
function CircularProgress({
  value,
  max,
  size = 96,
  strokeWidth = 8,
}: {
  value: number;
  max: number;
  size?: number;
  strokeWidth?: number;
}) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const percent = max > 0 ? value / max : 0;
  const offset = circumference * (1 - percent);

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width={size} height={size} className="-rotate-90">
        {/* Background circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={strokeWidth}
          className="text-muted"
        />
        {/* Progress arc */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className="text-primary transition-all duration-500"
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-2xl font-bold text-foreground">{value}</span>
        <span className="text-[10px] text-muted-foreground">Odpowiedziano</span>
      </div>
    </div>
  );
}

export function QuickStats({ stats }: QuickStatsProps) {
  return (
    <div className="space-y-4">
      <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        Statystyki
      </h3>

      {/* Circular progress */}
      <div className="flex justify-center">
        <CircularProgress value={stats.answered} max={stats.total} />
      </div>

      {/* Correct / Incorrect counters */}
      <div className="grid grid-cols-2 gap-2">
        <div className="rounded-xl border border-green-500/30 bg-green-500/10 p-3 text-center">
          <div className="text-2xl font-bold text-green-600 dark:text-green-400">
            {stats.correct}
          </div>
          <div className="text-xs text-green-700 dark:text-green-500">Poprawne</div>
        </div>
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-center">
          <div className="text-2xl font-bold text-red-600 dark:text-red-400">
            {stats.incorrect}
          </div>
          <div className="text-xs text-red-700 dark:text-red-500">Błędne</div>
        </div>
      </div>
    </div>
  );
}
