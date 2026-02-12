import { useCallback, useMemo, useState } from 'react';
import { questionBank } from '@/lib/data/questionBank';
import type {
  CurrentQuestionData,
  QuizConfig,
  QuizSession,
  QuizStats,
  QuestionStatus,
  SubjectProgress,
} from '@/lib/types/quiz';

// ---------------------------------------------------------------------------
// localStorage helpers
// ---------------------------------------------------------------------------

function storageKey(subjectName: string): string {
  return `quiz-progress-${subjectName}`;
}

function loadProgress(subjectName: string): SubjectProgress {
  try {
    const raw = localStorage.getItem(storageKey(subjectName));
    if (raw) return JSON.parse(raw) as SubjectProgress;
  } catch {
    /* ignore corrupted data */
  }
  return { answers: {}, incorrectIndices: [] };
}

function saveProgress(subjectName: string, progress: SubjectProgress): void {
  localStorage.setItem(storageKey(subjectName), JSON.stringify(progress));
}

// ---------------------------------------------------------------------------
// Random pick helper
// ---------------------------------------------------------------------------

function pickRandom<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

// ---------------------------------------------------------------------------
// Public helpers (for SubjectSelector)
// ---------------------------------------------------------------------------

export function getSubjectProgress(subjectName: string): SubjectProgress {
  return loadProgress(subjectName);
}

export function resetSubjectProgress(subjectName: string): void {
  localStorage.removeItem(storageKey(subjectName));
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useQuizSession(config: QuizConfig) {
  const subject = useMemo(
    () => questionBank.find((s) => s.name === config.subjectName)!,
    [config.subjectName],
  );

  // Build initial session
  const [session, setSession] = useState<QuizSession>(() => {
    const progress = loadProgress(config.subjectName);

    let indices: number[];
    if (config.mode === 'incorrectOnly') {
      indices = [...progress.incorrectIndices].sort((a, b) => a - b);
    } else {
      indices = subject.questions.map((_, i) => i);
    }

    // Pick a random first question
    const firstIndex = indices.length > 0 ? pickRandom(indices) : -1;

    return {
      subjectName: config.subjectName,
      mode: config.mode,
      availableIndices: indices,
      currentIndex: firstIndex,
      history: [],
      answers: {},
    };
  });

  // ---------------------------------------------------------------------------
  // Derived: visited set (history + current)
  // ---------------------------------------------------------------------------

  const visitedSet = useMemo(() => {
    const set = new Set(session.history);
    if (session.currentIndex >= 0) set.add(session.currentIndex);
    return set;
  }, [session.history, session.currentIndex]);

  const unvisitedIndices = useMemo(
    () => session.availableIndices.filter((idx) => !visitedSet.has(idx)),
    [session.availableIndices, visitedSet],
  );

  // ---------------------------------------------------------------------------
  // Derived data
  // ---------------------------------------------------------------------------

  const currentQuestionData: CurrentQuestionData | null = useMemo(() => {
    if (session.currentIndex < 0 || session.availableIndices.length === 0) return null;
    return {
      question: subject.questions[session.currentIndex],
      originalIndex: session.currentIndex,
      totalQuestions: session.availableIndices.length,
      sessionAnswer: session.answers[session.currentIndex],
    };
  }, [session, subject]);

  const stats: QuizStats = useMemo(() => {
    const answered = Object.values(session.answers).filter((a) => a.submitted).length;
    const correct = Object.values(session.answers).filter(
      (a) => a.submitted && a.isCorrect,
    ).length;
    return {
      total: session.availableIndices.length,
      answered,
      correct,
      incorrect: answered - correct,
    };
  }, [session]);

  /** Status map keyed by original question index */
  const questionStatusMap: Record<number, QuestionStatus> = useMemo(() => {
    const map: Record<number, QuestionStatus> = {};
    for (const idx of session.availableIndices) {
      if (idx === session.currentIndex) {
        map[idx] = 'current';
      } else {
        const ans = session.answers[idx];
        if (!ans?.submitted) {
          map[idx] = 'unanswered';
        } else {
          map[idx] = ans.isCorrect ? 'correct' : 'incorrect';
        }
      }
    }
    return map;
  }, [session]);

  // ---------------------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------------------

  const toggleAnswer = useCallback((answerIndex: number) => {
    setSession((prev) => {
      const origIdx = prev.currentIndex;
      const existing = prev.answers[origIdx];
      if (existing?.submitted) return prev;

      const selected = existing?.selectedAnswers ?? [];
      const next = selected.includes(answerIndex)
        ? selected.filter((i) => i !== answerIndex)
        : [...selected, answerIndex];

      return {
        ...prev,
        answers: {
          ...prev.answers,
          [origIdx]: {
            selectedAnswers: next,
            submitted: false,
            isCorrect: false,
          },
        },
      };
    });
  }, []);

  const submitAnswer = useCallback(() => {
    setSession((prev) => {
      const origIdx = prev.currentIndex;
      const existing = prev.answers[origIdx];
      if (!existing || existing.submitted) return prev;

      const question = subject.questions[origIdx];
      const correctIndices = question.answers
        .map((a, i) => (a.correct ? i : -1))
        .filter((i) => i !== -1);

      const isCorrect =
        correctIndices.length === existing.selectedAnswers.length &&
        correctIndices.every((i) => existing.selectedAnswers.includes(i));

      // Update localStorage progress
      const progress = loadProgress(prev.subjectName);
      progress.answers[origIdx] = {
        selectedAnswers: existing.selectedAnswers,
        isCorrect,
      };

      if (!isCorrect) {
        if (!progress.incorrectIndices.includes(origIdx)) {
          progress.incorrectIndices.push(origIdx);
        }
      } else if (prev.mode === 'incorrectOnly') {
        progress.incorrectIndices = progress.incorrectIndices.filter((i) => i !== origIdx);
      }

      saveProgress(prev.subjectName, progress);

      return {
        ...prev,
        answers: {
          ...prev.answers,
          [origIdx]: {
            ...existing,
            submitted: true,
            isCorrect,
          },
        },
      };
    });
  }, [subject]);

  /** Jump to a specific question by its original index */
  const goToQuestion = useCallback((originalIndex: number) => {
    setSession((prev) => {
      if (originalIndex === prev.currentIndex) return prev;
      if (!prev.availableIndices.includes(originalIndex)) return prev;
      return {
        ...prev,
        currentIndex: originalIndex,
        history: [...prev.history, prev.currentIndex],
      };
    });
  }, []);

  /** Pick a random unvisited question */
  const goNext = useCallback(() => {
    setSession((prev) => {
      const visited = new Set(prev.history);
      visited.add(prev.currentIndex);
      const unvisited = prev.availableIndices.filter((idx) => !visited.has(idx));

      if (unvisited.length === 0) return prev; // all visited

      const nextIdx = pickRandom(unvisited);
      return {
        ...prev,
        currentIndex: nextIdx,
        history: [...prev.history, prev.currentIndex],
      };
    });
  }, []);

  /** Go back to the previous question in visit history */
  const goPrevious = useCallback(() => {
    setSession((prev) => {
      if (prev.history.length === 0) return prev;
      const newHistory = [...prev.history];
      const prevIndex = newHistory.pop()!;
      return {
        ...prev,
        currentIndex: prevIndex,
        history: newHistory,
      };
    });
  }, []);

  return {
    session,
    currentQuestion: currentQuestionData,
    stats,
    questionStatusMap,
    hasNext: unvisitedIndices.length > 0,
    hasPrevious: session.history.length > 0,
    toggleAnswer,
    submitAnswer,
    goToQuestion,
    goNext,
    goPrevious,
  };
}
