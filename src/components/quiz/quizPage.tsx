import { QuizHeader } from '@/components/quiz/quizHeader';
import { QuestionCard } from '@/components/quiz/questionCard';
import { QuizNavigation } from '@/components/quiz/quizNavigation';
import { QuizSidebar } from '@/components/quiz/quizSidebar';
import { useQuizSession } from '@/lib/hooks/useQuizSession';
import type { QuizConfig } from '@/lib/types/quiz';

interface QuizPageProps {
  config: QuizConfig;
  onFinish: () => void;
}

export function QuizPage({ config, onFinish }: QuizPageProps) {
  const {
    session,
    currentQuestion,
    stats,
    questionStatusMap,
    hasNext,
    hasPrevious,
    toggleAnswer,
    submitAnswer,
    goToQuestion,
    goNext,
    goPrevious,
  } = useQuizSession(config);

  // Edge case: no questions available (e.g. empty incorrect pool)
  if (!currentQuestion) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-background px-4 text-center">
        <h2 className="text-xl font-semibold text-foreground">
          Brak pytań do wyświetlenia
        </h2>
        <p className="text-muted-foreground">
          {config.mode === 'incorrectOnly'
            ? 'Nie masz żadnych błędnie odpowiedzianych pytań w tym przedmiocie.'
            : 'Ten przedmiot nie zawiera pytań.'}
        </p>
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
    <div className="flex min-h-screen flex-col bg-background">
      {/* Top bar */}
      <QuizHeader
        subjectName={config.subjectName}
        currentIndex={currentQuestion.originalIndex}
        stats={stats}
        onFinish={onFinish}
      />

      {/* Main content */}
      <div className="mx-auto flex w-full max-w-7xl flex-1 gap-6 px-4 py-6 sm:px-6 lg:gap-8">
        {/* Left column: question + navigation */}
        <main className="min-w-0 flex-1">
          <QuestionCard data={currentQuestion} onToggleAnswer={toggleAnswer} />
          <QuizNavigation
            sessionAnswer={currentQuestion.sessionAnswer}
            hasPrevious={hasPrevious}
            hasNext={hasNext}
            onPrevious={goPrevious}
            onNext={goNext}
            onSubmit={submitAnswer}
          />
        </main>

        {/* Right column: sidebar (hidden on small screens, shown on lg+) */}
        <div className="hidden w-72 shrink-0 lg:block">
          <div className="sticky top-6">
            <QuizSidebar
              stats={stats}
              availableIndices={session.availableIndices}
              currentIndex={session.currentIndex}
              statusMap={questionStatusMap}
              onGoToQuestion={goToQuestion}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
