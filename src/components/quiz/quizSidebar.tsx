import { QuickStats } from '@/components/quiz/quickStats';
import { QuestionMap } from '@/components/quiz/questionMap';
import { Separator } from '@/components/ui/separator';
import type { QuizStats, QuestionStatus } from '@/lib/types/quiz';

interface QuizSidebarProps {
  stats: QuizStats;
  availableIndices: number[];
  currentIndex: number;
  statusMap: Record<number, QuestionStatus>;
  onGoToQuestion: (originalIndex: number) => void;
}

export function QuizSidebar({
  stats,
  availableIndices,
  currentIndex,
  statusMap,
  onGoToQuestion,
}: QuizSidebarProps) {
  return (
    <aside className="space-y-6 rounded-2xl border border-border bg-card p-5">
      <QuickStats stats={stats} />
      <Separator />
      <QuestionMap
        availableIndices={availableIndices}
        currentIndex={currentIndex}
        statusMap={statusMap}
        onGoTo={onGoToQuestion}
      />
    </aside>
  );
}
