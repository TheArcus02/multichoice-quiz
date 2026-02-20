import { useState } from 'react';
import { BookOpen, RotateCcw, Play, RefreshCw } from 'lucide-react';
import { questionBank } from '@/lib/data/questionBank';
import { getSubjectProgress, resetSubjectProgress } from '@/lib/hooks/useQuizSession';
import type { QuizConfig, QuizMode } from '@/lib/types/quiz';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';

interface SubjectSelectorProps {
  onStart: (config: QuizConfig) => void;
  onStartExam: (subjectName: string) => void;
}

export function SubjectSelector({ onStart, onStartExam }: SubjectSelectorProps) {
  // Force re-render after reset
  const [, setTick] = useState(0);

  function handleStart(subjectName: string, mode: QuizMode) {
    onStart({ subjectName, mode });
  }

  function handleStartExam(subjectName: string) {
    onStartExam(subjectName);
  }

  function handleReset(subjectName: string) {
    resetSubjectProgress(subjectName);
    setTick((t) => t + 1);
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="mx-auto max-w-3xl px-4 py-12">
        {/* Header */}
        <div className="mb-10 text-center">
          <div className="mb-4 inline-flex items-center gap-2 rounded-full bg-primary/10 px-4 py-2 text-primary">
            <BookOpen className="size-5" />
            <span className="text-sm font-medium">Quiz App</span>
          </div>
          <h1 className="text-3xl font-bold tracking-tight text-foreground sm:text-4xl">
            Wybierz przedmiot
          </h1>
          <p className="mt-2 text-muted-foreground">
            Wybierz zestaw pytań i rozpocznij naukę
          </p>
        </div>

        {/* Subject Cards */}
        <div className="grid gap-4">
          {questionBank.map((subject) => {
            const progress = getSubjectProgress(subject.name);
            const totalQuestions = subject.questions.length;
            const answeredCount = Object.keys(progress.answers).length;
            const correctCount = Object.values(progress.answers).filter(
              (a) => a.isCorrect,
            ).length;
            const incorrectCount = progress.incorrectIndices.length;
            const canStartExam = totalQuestions >= 15;

            return (
              <Card key={subject.name}>
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div>
                      <CardTitle className="text-xl">{subject.name}</CardTitle>
                      <CardDescription className="mt-1">
                        {totalQuestions} pytań
                      </CardDescription>
                    </div>
                    {answeredCount > 0 && (
                      <div className="flex gap-2">
                        <Badge variant="outline">
                          {answeredCount}/{totalQuestions} odpowiedziano
                        </Badge>
                      </div>
                    )}
                  </div>
                </CardHeader>

                <CardContent>
                  {/* Progress stats */}
                  {answeredCount > 0 && (
                    <div className="mb-4 flex gap-3">
                      <div className="flex items-center gap-1.5 text-sm">
                        <span className="inline-block size-2.5 rounded-full bg-green-500" />
                        <span className="text-muted-foreground">
                          Poprawne: <span className="font-medium text-foreground">{correctCount}</span>
                        </span>
                      </div>
                      <div className="flex items-center gap-1.5 text-sm">
                        <span className="inline-block size-2.5 rounded-full bg-red-500" />
                        <span className="text-muted-foreground">
                          Błędne: <span className="font-medium text-foreground">{incorrectCount}</span>
                        </span>
                      </div>
                    </div>
                  )}

                  {/* Actions */}
                  <div className="flex flex-wrap gap-2">
                    <Button onClick={() => handleStart(subject.name, 'all')}>
                      <Play className="size-4" data-icon="inline-start" />
                      Wszystkie pytania
                    </Button>
                    {canStartExam && (
                      <Button variant="outline" onClick={() => handleStartExam(subject.name)}>
                        Egzamin (15 pytań)
                      </Button>
                    )}
                    <Button
                      variant="secondary"
                      onClick={() => handleStart(subject.name, 'incorrectOnly')}
                      disabled={incorrectCount === 0}
                    >
                      <RefreshCw className="size-4" data-icon="inline-start" />
                      Tylko błędne ({incorrectCount})
                    </Button>

                    {answeredCount > 0 && (
                      <AlertDialog>
                        <AlertDialogTrigger
                          render={
                            <Button variant="ghost" className="text-destructive">
                              <RotateCcw className="size-4" data-icon="inline-start" />
                              Reset
                            </Button>
                          }
                        />
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Resetować postęp?</AlertDialogTitle>
                            <AlertDialogDescription>
                              Cały postęp dla przedmiotu &ldquo;{subject.name}&rdquo; zostanie
                              usunięty. Tej operacji nie można cofnąć.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Anuluj</AlertDialogCancel>
                            <AlertDialogAction
                              variant="destructive"
                              onClick={() => handleReset(subject.name)}
                            >
                              Resetuj
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    )}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>
    </div>
  );
}
