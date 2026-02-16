import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { AnswerOption } from '@/components/quiz/answerOption';
import type { CurrentQuestionData } from '@/lib/types/quiz';
import { Check, Copy } from 'lucide-react';
import { useState } from 'react';

interface QuestionCardProps {
  data: CurrentQuestionData;
  onToggleAnswer: (answerIndex: number) => void;
}

export function QuestionCard({ data, onToggleAnswer }: QuestionCardProps) {
  const { question, sessionAnswer } = data;
  const submitted = sessionAnswer?.submitted ?? false;
  const selectedAnswers = sessionAnswer?.selectedAnswers ?? [];
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'error'>('idle');

  const copyPayload = [
    question.text,
    '',
    ...question.answers.map((answer, index) => `${String.fromCharCode(65 + index)}. ${answer.text}`),
  ].join('\n');

  const handleCopyQuestion = async () => {
    try {
      await navigator.clipboard.writeText(copyPayload);
      setCopyState('copied');
    } catch {
      setCopyState('error');
    }

    window.setTimeout(() => setCopyState('idle'), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Badge */}
      <Badge variant="secondary">MULTIPLE CHOICE</Badge>

      {/* Question text */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <h2 className="text-xl font-semibold leading-snug text-foreground sm:text-2xl">
          {question.text}
        </h2>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="sm:shrink-0"
          onClick={handleCopyQuestion}
        >
          {copyState === 'copied' ? (
            <>
              <Check className="size-4" data-icon="inline-start" />
              Skopiowano
            </>
          ) : (
            <>
              <Copy className="size-4" data-icon="inline-start" />
              {copyState === 'error' ? 'Błąd kopiowania' : 'Kopiuj'}
            </>
          )}
        </Button>
      </div>

      {/* Answer options */}
      <div className="space-y-3">
        {question.answers.map((answer, i) => (
          <AnswerOption
            key={i}
            index={i}
            text={answer.text}
            isSelected={selectedAnswers.includes(i)}
            isCorrectAnswer={answer.correct}
            submitted={submitted}
            disabled={submitted}
            onToggle={() => onToggleAnswer(i)}
          />
        ))}
      </div>

      {/* Post-submit feedback */}
      {submitted && (
        <div
          className={
            sessionAnswer?.isCorrect
              ? 'rounded-xl border border-green-500/30 bg-green-500/10 px-4 py-3 text-sm text-green-700 dark:text-green-400'
              : 'rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-700 dark:text-red-400'
          }
        >
          {sessionAnswer?.isCorrect
            ? 'Poprawna odpowiedź!'
            : 'Niepoprawna odpowiedź. Poprawne odpowiedzi zostały zaznaczone na zielono.'}
        </div>
      )}
    </div>
  );
}
