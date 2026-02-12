import { ArrowLeft, ArrowRight, CheckCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { SessionAnswer } from '@/lib/types/quiz';

interface QuizNavigationProps {
  sessionAnswer: SessionAnswer | undefined;
  hasPrevious: boolean;
  hasNext: boolean;
  onPrevious: () => void;
  onNext: () => void;
  onSubmit: () => void;
}

export function QuizNavigation({
  sessionAnswer,
  hasPrevious,
  hasNext,
  onPrevious,
  onNext,
  onSubmit,
}: QuizNavigationProps) {
  const hasSelection = (sessionAnswer?.selectedAnswers.length ?? 0) > 0;
  const submitted = sessionAnswer?.submitted ?? false;

  return (
    <div className="mt-8 flex items-center justify-between border-t border-border pt-6">
      {/* Previous */}
      <Button variant="ghost" disabled={!hasPrevious} onClick={onPrevious}>
        <ArrowLeft className="size-4" data-icon="inline-start" />
        Poprzednie
      </Button>

      {/* Submit or Next */}
      <div className="flex gap-2">
        {!submitted && hasSelection && (
          <Button onClick={onSubmit}>
            <CheckCircle className="size-4" data-icon="inline-start" />
            Sprawdź odpowiedź
          </Button>
        )}
        {(submitted || !hasSelection) && (
          <Button
            onClick={onNext}
            disabled={!hasNext}
            variant={submitted ? 'default' : 'secondary'}
          >
            Następne pytanie
            <ArrowRight className="size-4" data-icon="inline-end" />
          </Button>
        )}
      </div>
    </div>
  );
}
