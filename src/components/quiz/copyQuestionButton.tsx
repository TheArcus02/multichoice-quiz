import { Button } from '@/components/ui/button';
import type { Question } from '@/lib/data/questionBank';
import { Check, Copy } from 'lucide-react';
import { useState } from 'react';

interface CopyQuestionButtonProps {
  question: Question;
  className?: string;
}

export function CopyQuestionButton({ question, className }: CopyQuestionButtonProps) {
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'error'>('idle');

  const copyPayload = [
    question.text,
    '',
    ...question.answers.map(
      (answer, index) => `${String.fromCharCode(65 + index)}. ${answer.text}`,
    ),
  ].join('\n');

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
