import { useState } from 'react';
import { SubjectSelector } from '@/components/subjectSelector';
import { QuizPage } from '@/components/quiz/quizPage';
import type { QuizConfig } from '@/lib/types/quiz';
import { ExamPage } from '@/components/exam/ExamPage';

type View =
  | { kind: 'select' }
  | { kind: 'quiz'; config: QuizConfig }
  | { kind: 'exam'; subjectName: string };

export function App() {
  const [view, setView] = useState<View>({ kind: 'select' });

  if (view.kind === 'quiz') {
    return (
      <QuizPage
        config={view.config}
        onFinish={() => setView({ kind: 'select' })}
      />
    );
  }

  if (view.kind === 'exam') {
    return (
      <ExamPage
        subjectName={view.subjectName}
        onFinish={() => setView({ kind: 'select' })}
      />
    );
  }

  return (
    <SubjectSelector
      onStart={(config) => setView({ kind: 'quiz', config })}
      onStartExam={(subjectName) => setView({ kind: 'exam', subjectName })}
    />
  );
}

export default App;
