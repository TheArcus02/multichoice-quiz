import { useMemo } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { AnswerOption } from '@/components/quiz/answerOption';
import { useExamSession } from '@/lib/hooks/useExamSession';

interface ExamPageProps {
  subjectName: string;
  onFinish: () => void;
}

function formatDuration(ms: number): string {
  const totalSeconds = Math.floor(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

export function ExamPage({ subjectName, onFinish }: ExamPageProps) {
  const { questionData, toggleAnswer, finishExam, result, elapsedMs } =
    useExamSession(subjectName);

  const submitted = Boolean(result);
  const displayTime = useMemo(
    () => formatDuration(result?.timeElapsedMs ?? elapsedMs),
    [elapsedMs, result?.timeElapsedMs],
  );

  if (questionData.length === 0) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-background px-4 text-center">
        <h2 className="text-xl font-semibold text-foreground">
          Brak pytań do wyświetlenia
        </h2>
        <button
          type="button"
          onClick={onFinish}
          className="text-primary underline underline-offset-4"
        >
          Wróć do wyboru przedmiotu
        </button>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="mx-auto w-full max-w-4xl px-4 py-8 sm:px-6">
        <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
          <div>
            <Badge variant="secondary">EGZAMIN</Badge>
            <h1 className="mt-2 text-2xl font-semibold text-foreground sm:text-3xl">
              {subjectName}
            </h1>
            <p className="text-sm text-muted-foreground">
              {questionData.length} pytań
            </p>
          </div>
          <div className="rounded-lg border border-border bg-card px-4 py-2 text-center">
            <div className="text-xs text-muted-foreground">Czas</div>
            <div className="text-lg font-semibold text-foreground">{displayTime}</div>
          </div>
        </div>

        {submitted && result && (
          <div className="mb-8 rounded-xl border border-border bg-card p-5">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <div className="text-sm text-muted-foreground">Wynik</div>
                <div className="text-2xl font-semibold text-foreground">
                  {result.totalScore.toFixed(2)} / {result.maxScore}
                </div>
              </div>
              <Badge variant={result.passed ? 'default' : 'destructive'}>
                {result.passed ? 'Zaliczone' : 'Nie zaliczone'}
              </Badge>
            </div>
            <div className="mt-4 flex flex-wrap gap-3 text-xs text-muted-foreground">
              <div className="flex items-center gap-2">
                <span className="size-2.5 rounded-full bg-green-500" />
                <span>Poprawna, zaznaczona</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="size-2.5 rounded-full bg-amber-500" />
                <span>Poprawna, niezaznaczona</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="size-2.5 rounded-full bg-red-500" />
                <span>Błędna, zaznaczona</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="size-2.5 rounded-full border border-border bg-muted" />
                <span>Błędna, niezaznaczona</span>
              </div>
            </div>
          </div>
        )}

        <div className="space-y-8">
          {questionData.map(({ order, questionIndex, question, selectedAnswers, answerOrder }) => {
            const questionResult = result?.questions.find(
              (q) => q.questionIndex === questionIndex,
            );
            return (
              <div key={questionIndex} className="rounded-xl border border-border bg-card p-5">
                <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="text-xs font-semibold text-muted-foreground">
                      Pytanie {order + 1}
                    </div>
                    <h2 className="mt-1 text-lg font-semibold text-foreground">
                      {question.text}
                    </h2>
                  </div>
                  {submitted && questionResult && (
                    <Badge variant="outline">
                      {questionResult.score.toFixed(2)} / 1
                    </Badge>
                  )}
                </div>

                <div className="space-y-3">
                  {answerOrder.map((originalIndex, displayIndex) => {
                    const answer = question.answers[originalIndex];
                    return (
                      <AnswerOption
                        key={originalIndex}
                        index={displayIndex}
                        text={answer.text}
                        isSelected={selectedAnswers.includes(originalIndex)}
                        isCorrectAnswer={answer.correct}
                        submitted={submitted}
                        disabled={submitted}
                        onToggle={() => toggleAnswer(questionIndex, originalIndex)}
                      />
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>

        <div className="mt-8 flex justify-end">
          {submitted ? (
            <Button onClick={onFinish}>Wróć do wyboru przedmiotu</Button>
          ) : (
            <Button onClick={finishExam}>Zakończ egzamin</Button>
          )}
        </div>
      </div>
    </div>
  );
}
