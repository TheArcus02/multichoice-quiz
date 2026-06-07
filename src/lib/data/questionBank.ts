import { questions4_0 } from "./40-questions.js";
import { aiQuestions } from "./ai.js";
import { bsiLabQuestions } from "./bsi-lab.js";
import { questions as bsiQuestions } from "./question.js";

export interface Answer {
  text: string;
  correct: boolean;
}

export interface Question {
  text: string;
  answers: Answer[];
}

export type AnswerMode = "single" | "multiple";

export interface Subject {
  name: string;
  questions: Question[];
  /** Domyślnie multiple. */
  answerMode?: AnswerMode;
  /** Domyślnie 15. */
  examQuestionCount?: number;
}

/**
 * Mapa przedmiotów. Aby dodać nowy przedmiot:
 * 1. Utwórz plik z pytaniami w data/ (np. data/pytaniaSK.ts)
 * 2. Zaimportuj go tutaj
 * 3. Dodaj wpis do tablicy questionBank
 */
export const questionBank: Subject[] = [
  {
    name: "BSI",
    questions: bsiQuestions,
  },
  {
    name: "Przemysł 4.0",
    questions: questions4_0,
  },
  {
    name: "BSI Lab",
    questions: bsiLabQuestions,
    examQuestionCount: 12,
  },
  {
    name: "Sieci Neuronowe",
    questions: aiQuestions,
    answerMode: "single",
    examQuestionCount: 15,
  },
];
