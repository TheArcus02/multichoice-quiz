import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { questionBank } from '@/lib/data/questionBank';
import type { ExamQuestionResult, ExamResult } from '@/lib/types/quiz';

const DEFAULT_EXAM_QUESTION_COUNT = 15;

function shuffle<T>(arr: T[]): T[] {
  const copy = [...arr];
  for (let i = copy.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
}

function roundToQuarter(value: number): number {
  return Math.round(value * 4) / 4;
}

function clampScore(value: number): number {
  return Math.max(0, Math.min(1, value));
}

function calculateQuestionScore(
  correctCount: number,
  wrongCount: number,
  selectedCorrect: number,
  selectedWrong: number,
): number {
  const correctPart = correctCount > 0 ? selectedCorrect / correctCount : 0;
  const wrongPart = wrongCount > 0 ? selectedWrong / wrongCount : 0;
  const raw = correctPart - wrongPart;
  return roundToQuarter(clampScore(raw));
}

export function useExamSession(subjectName: string, count?: number) {
  const subject = useMemo(
    () => questionBank.find((s) => s.name === subjectName)!,
    [subjectName],
  );
  const answerMode = subject.answerMode ?? 'multiple';

  const examCount =
    count ?? subject.examQuestionCount ?? DEFAULT_EXAM_QUESTION_COUNT;

  const [questionIndices] = useState<number[]>(() => {
    const indices = subject.questions.map((_, i) => i);
    const shuffled = shuffle(indices);
    return shuffled.slice(0, Math.min(examCount, shuffled.length));
  });

  const [answers, setAnswers] = useState<Record<number, number[]>>(() =>
    Object.fromEntries(questionIndices.map((idx) => [idx, []])),
  );

  const [answerOrders] = useState<Record<number, number[]>>(() =>
    Object.fromEntries(
      questionIndices.map((idx) => [
        idx,
        shuffle(subject.questions[idx].answers.map((_, i) => i)),
      ]),
    ),
  );

  const [result, setResult] = useState<ExamResult | null>(null);
  const startTimeRef = useRef<number>(0);
  const [elapsedMs, setElapsedMs] = useState(0);

  useEffect(() => {
    if (startTimeRef.current === 0) {
      startTimeRef.current = Date.now();
    }
    if (result) {
      return;
    }
    const interval = window.setInterval(() => {
      setElapsedMs(Date.now() - startTimeRef.current);
    }, 1000);
    return () => window.clearInterval(interval);
  }, [result]);

  const toggleAnswer = useCallback((questionIndex: number, answerIndex: number) => {
    setAnswers((prev) => {
      if (result) return prev;
      const selected = prev[questionIndex] ?? [];
      const next =
        answerMode === 'single'
          ? [answerIndex]
          : selected.includes(answerIndex)
            ? selected.filter((i) => i !== answerIndex)
            : [...selected, answerIndex];
      return {
        ...prev,
        [questionIndex]: next,
      };
    });
  }, [answerMode, result]);

  const finishExam = useCallback(() => {
    if (result) return result;

    const questionResults: ExamQuestionResult[] = questionIndices.map((idx) => {
      const question = subject.questions[idx];
      const selected = answers[idx] ?? [];
      const correctIndices = question.answers
        .map((a, i) => (a.correct ? i : -1))
        .filter((i) => i !== -1);
      const wrongIndices = question.answers
        .map((a, i) => (!a.correct ? i : -1))
        .filter((i) => i !== -1);
      const selectedCorrect = selected.filter((i) => correctIndices.includes(i)).length;
      const selectedWrong = selected.filter((i) => wrongIndices.includes(i)).length;
      const score =
        answerMode === 'single'
          ? selected.some((i) => question.answers[i]?.correct)
            ? 1
            : 0
          : calculateQuestionScore(
              correctIndices.length,
              wrongIndices.length,
              selectedCorrect,
              selectedWrong,
            );

      return {
        questionIndex: idx,
        selectedAnswers: selected,
        score,
        maxScore: 1,
      };
    });

    const totalScore = roundToQuarter(
      questionResults.reduce((sum, item) => sum + item.score, 0),
    );
    const maxScore = questionIndices.length;
    const passingThreshold = roundToQuarter(maxScore * 0.5);
    const timeElapsedMs = Date.now() - startTimeRef.current;
    const nextResult: ExamResult = {
      totalScore,
      maxScore,
      passed: totalScore >= passingThreshold,
      timeElapsedMs,
      questions: questionResults,
    };
    setElapsedMs(timeElapsedMs);
    setResult(nextResult);
    return nextResult;
  }, [answerMode, answers, questionIndices, result, subject.questions]);

  const questionData = useMemo(
    () =>
      questionIndices.map((idx, order) => ({
        order,
        questionIndex: idx,
        question: subject.questions[idx],
        selectedAnswers: answers[idx] ?? [],
        answerOrder: answerOrders[idx],
      })),
    [answers, answerOrders, questionIndices, subject.questions],
  );

  return {
    subjectName,
    answerMode,
    questionData,
    answers,
    toggleAnswer,
    finishExam,
    result,
    elapsedMs,
  };
}
