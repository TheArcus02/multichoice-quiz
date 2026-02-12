import { Check, X } from 'lucide-react';
import { cn } from '@/lib/utils';

const LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

interface AnswerOptionProps {
  index: number;
  text: string;
  isSelected: boolean;
  isCorrectAnswer: boolean;
  submitted: boolean;
  disabled: boolean;
  onToggle: () => void;
}

export function AnswerOption({
  index,
  text,
  isSelected,
  isCorrectAnswer,
  submitted,
  disabled,
  onToggle,
}: AnswerOptionProps) {
  const letter = LETTERS[index] ?? '?';

  let borderColor = 'border-border';
  let bgColor = 'bg-card';
  let ringClass = '';
  let icon: React.ReactNode = null;

  if (submitted) {
    if (isCorrectAnswer) {
      borderColor = 'border-green-500';
      bgColor = 'bg-green-500/10';
      icon = <Check className="size-4 text-green-500" />;
    } else if (isSelected && !isCorrectAnswer) {
      borderColor = 'border-red-500';
      bgColor = 'bg-red-500/10';
      icon = <X className="size-4 text-red-500" />;
    }
  } else if (isSelected) {
    borderColor = 'border-primary';
    ringClass = 'ring-2 ring-primary/20';
    bgColor = 'bg-primary/5';
  }

  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onToggle}
      className={cn(
        'flex w-full items-center gap-3 rounded-xl border px-4 py-3.5 text-left transition-all',
        borderColor,
        bgColor,
        ringClass,
        !disabled && 'cursor-pointer hover:border-primary/50 hover:bg-muted/50',
        disabled && 'cursor-default',
      )}
    >
      {/* Checkbox indicator */}
      <span
        className={cn(
          'flex size-6 shrink-0 items-center justify-center rounded-md border text-xs font-medium transition-colors',
          submitted && isCorrectAnswer
            ? 'border-green-500 bg-green-500 text-white'
            : submitted && isSelected && !isCorrectAnswer
              ? 'border-red-500 bg-red-500 text-white'
              : isSelected
                ? 'border-primary bg-primary text-primary-foreground'
                : 'border-border bg-background text-muted-foreground',
        )}
      >
        {submitted && (isCorrectAnswer || (isSelected && !isCorrectAnswer))
          ? icon
          : isSelected
            ? <Check className="size-3.5" />
            : letter}
      </span>

      {/* Answer text */}
      <span className="flex-1 text-sm text-foreground">{text}</span>

      {/* Letter badge on the right */}
      <span className="shrink-0 text-xs font-medium text-muted-foreground">
        {letter}
      </span>
    </button>
  );
}
