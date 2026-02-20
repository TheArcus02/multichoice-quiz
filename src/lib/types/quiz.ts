import type { Question } from '@/lib/data/questionBank';

// --- Persisted in localStorage ---

export interface QuestionResult {
  selectedAnswers: number[];
  isCorrect: boolean;
}

export interface SubjectProgress {
  /** Keyed by original question index in the subject */
  answers: Record<number, QuestionResult>;
  /** Indices of questions that were answered incorrectly at least once */
  incorrectIndices: number[];
}

// --- Runtime session state ---

export type QuizMode = 'all' | 'incorrectOnly';

export interface SessionAnswer {
  selectedAnswers: number[];
  submitted: boolean;
  isCorrect: boolean;
}

export interface QuizSession {
  subjectName: string;
  mode: QuizMode;
  /** All available question indices in original order */
  availableIndices: number[];
  /** Original question index currently being shown */
  currentIndex: number;
  /** Back-stack of previously visited original indices (for "Previous") */
  history: number[];
  /** Keyed by original question index */
  answers: Record<number, SessionAnswer>;
}

// --- Derived helpers ---

export type QuestionStatus = 'unanswered' | 'correct' | 'incorrect' | 'current';

export interface QuizStats {
  total: number;
  answered: number;
  correct: number;
  incorrect: number;
}

export interface QuizConfig {
  subjectName: string;
  mode: QuizMode;
}

export interface CurrentQuestionData {
  question: Question;
  originalIndex: number;
  totalQuestions: number;
  sessionAnswer: SessionAnswer | undefined;
}

// --- Exam mode ---

export interface ExamAnswer {
  selectedAnswers: number[];
}

export interface ExamQuestionResult {
  questionIndex: number;
  selectedAnswers: number[];
  score: number;
  maxScore: 1;
}

export interface ExamResult {
  totalScore: number;
  maxScore: 15;
  passed: boolean;
  timeElapsedMs: number;
  questions: ExamQuestionResult[];
}
