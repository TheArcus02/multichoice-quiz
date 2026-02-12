import { useState, useMemo } from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { QuestionStatus } from '@/lib/types/quiz';

const PAGE_SIZE = 25; // 5x5 grid per page

interface QuestionMapProps {
  /** All available question indices in original order */
  availableIndices: number[];
  /** Original index of the current question */
  currentIndex: number;
  /** Status keyed by original question index */
  statusMap: Record<number, QuestionStatus>;
  /** Jump to a question by its original index */
  onGoTo: (originalIndex: number) => void;
}

const statusColors: Record<QuestionStatus, string> = {
  unanswered: 'bg-muted text-muted-foreground hover:bg-muted/80',
  current: 'bg-primary text-primary-foreground ring-2 ring-primary/40',
  correct: 'bg-green-500 text-white hover:bg-green-600',
  incorrect: 'bg-red-500 text-white hover:bg-red-600',
};

export function QuestionMap({
  availableIndices,
  currentIndex,
  statusMap,
  onGoTo,
}: QuestionMapProps) {
  const totalPages = Math.ceil(availableIndices.length / PAGE_SIZE);
  const needsPagination = totalPages > 1;

  // Which page does the current question live on?
  const currentPageForQuestion = useMemo(() => {
    const pos = availableIndices.indexOf(currentIndex);
    return pos >= 0 ? Math.floor(pos / PAGE_SIZE) : 0;
  }, [availableIndices, currentIndex]);

  // Manual page override is tied to the currentIndex it was set for.
  // When currentIndex changes (e.g. random Next), the override is automatically ignored.
  const [manualOverride, setManualOverride] = useState<{
    page: number;
    forIndex: number;
  } | null>(null);

  const activePage =
    manualOverride !== null && manualOverride.forIndex === currentIndex
      ? manualOverride.page
      : currentPageForQuestion;

  const pageItems = useMemo(() => {
    const start = activePage * PAGE_SIZE;
    return availableIndices.slice(start, start + PAGE_SIZE);
  }, [availableIndices, activePage]);

  function goPage(dir: -1 | 1) {
    const next = activePage + dir;
    if (next < 0 || next >= totalPages) return;
    setManualOverride({ page: next, forIndex: currentIndex });
  }

  return (
    <div className="space-y-3">
      {/* Header with pagination controls */}
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Mapa pytań
        </h3>
        {needsPagination && (
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => goPage(-1)}
              disabled={activePage === 0}
              className="flex size-6 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-muted disabled:opacity-30"
            >
              <ChevronLeft className="size-3.5" />
            </button>
            <span className="min-w-[3ch] text-center text-[10px] text-muted-foreground">
              {activePage + 1}/{totalPages}
            </span>
            <button
              type="button"
              onClick={() => goPage(1)}
              disabled={activePage === totalPages - 1}
              className="flex size-6 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-muted disabled:opacity-30"
            >
              <ChevronRight className="size-3.5" />
            </button>
          </div>
        )}
      </div>

      {/* Grid -- numbers correspond to original question indices */}
      <div className="grid grid-cols-5 gap-1.5">
        {pageItems.map((origIdx) => {
          const status = statusMap[origIdx] ?? 'unanswered';
          return (
            <button
              key={origIdx}
              type="button"
              onClick={() => onGoTo(origIdx)}
              className={cn(
                'flex size-9 items-center justify-center rounded-lg text-xs font-medium transition-colors',
                statusColors[status],
              )}
            >
              {origIdx + 1}
            </button>
          );
        })}
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-x-3 gap-y-1 pt-1">
        <LegendItem color="bg-muted" label="Bez odpowiedzi" />
        <LegendItem color="bg-primary" label="Aktualne" />
        <LegendItem color="bg-green-500" label="Poprawne" />
        <LegendItem color="bg-red-500" label="Błędne" />
      </div>
    </div>
  );
}

function LegendItem({ color, label }: { color: string; label: string }) {
  return (
    <div className="flex items-center gap-1">
      <span className={cn('inline-block size-2.5 rounded-sm', color)} />
      <span className="text-[10px] text-muted-foreground">{label}</span>
    </div>
  );
}
