import { Button } from '@/components/ui/button';
import type { Question } from '@/lib/data/questionBank';
import { Check, Copy } from 'lucide-react';
import { useState } from 'react';

interface CopyQuestionButtonProps {
  question: Question;
  className?: string;
  /** Domyślnie treść A/B/C jako tekst; w egzaminie — obiekt pytania jako JSON. */
  format?: 'plain' | 'json';
}

function buildPlainPayload(question: Question): string {
  return [
    question.text,
    '',
    ...question.answers.map(
      (answer, index) => `${String.fromCharCode(65 + index)}. ${answer.text}`,
    ),
  ].join('\n');
}

function buildJsonPayload(question: Question): string {
  return JSON.stringify(
    {
      text: question.text,
      answers: question.answers.map((a) => ({
        text: a.text,
        correct: a.correct,
      })),
    },
    null,
    2,
  );
}

export function CopyQuestionButton({
  question,
  className,
  format = 'plain',
}: CopyQuestionButtonProps) {
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'error'>('idle');

  const copyPayload = format === 'json' ? buildJsonPayload(question) : buildPlainPayload(question);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(copyPayload);
      setCopyState('copied');
    } catch {
      setCopyState('error');
    }

    window.setTimeout(() => setCopyState('idle'), 2000);
  };

  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      className={className}
      onClick={handleCopy}
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
  );
}
