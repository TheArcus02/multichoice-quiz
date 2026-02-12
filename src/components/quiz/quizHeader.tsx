import { LogOut } from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { QuizStats } from '@/lib/types/quiz';

interface QuizHeaderProps {
  subjectName: string;
  /** Original question index (0-based) */
  currentIndex: number;
  stats: QuizStats;
  onFinish: () => void;
}

export function QuizHeader({
  subjectName,
  currentIndex,
  stats,
  onFinish,
}: QuizHeaderProps) {
  const progressPercent = stats.total > 0
    ? Math.round((stats.answered / stats.total) * 100)
    : 0;

  return (
    <header className="border-b border-border bg-card/80 backdrop-blur-sm">
      <div className="mx-auto flex max-w-7xl items-center gap-4 px-4 py-3 sm:px-6">
        {/* Subject name */}
        <div className="min-w-0 shrink-0">
          <h1 className="truncate text-sm font-semibold text-foreground">
            {subjectName}
          </h1>
        </div>

        {/* Question counter + progress */}
        <div className="flex flex-1 items-center gap-3">
          <span className="whitespace-nowrap text-xs text-muted-foreground">
            Pytanie {currentIndex + 1} &middot; {stats.answered}/{stats.total} odpowiedziano
          </span>
          <div className="hidden h-2 flex-1 overflow-hidden rounded-full bg-muted sm:block">
            <div
              className="h-full rounded-full bg-primary transition-all duration-300"
              style={{ width: `${progressPercent}%` }}
            />
          </div>
        </div>

        {/* Finish button */}
        <Button variant="destructive" size="sm" onClick={onFinish}>
          <LogOut className="size-4" data-icon="inline-start" />
          Zakończ
        </Button>
      </div>
    </header>
  );
}
