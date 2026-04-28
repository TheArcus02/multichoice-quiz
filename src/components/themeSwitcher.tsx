import { useEffect, useState } from 'react';
import { Moon, Sun } from 'lucide-react';
import { Button } from '@/components/ui/button';

const STORAGE_KEY = 'quiz-theme';

function readIsDark(): boolean {
  if (typeof document === 'undefined') return true;
  return document.documentElement.classList.contains('dark');
}

export function ThemeSwitcher() {
  const [isDark, setIsDark] = useState(readIsDark);

  useEffect(() => {
    document.documentElement.classList.toggle('dark', isDark);
    try {
      localStorage.setItem(STORAGE_KEY, isDark ? 'dark' : 'light');
    } catch {
      /* ignore */
    }
  }, [isDark]);

  return (
    <Button
      type="button"
      variant="outline"
      size="icon"
      className="fixed bottom-4 left-4 z-50 size-11 rounded-full border-border bg-card/80 shadow-md backdrop-blur-sm"
      onClick={() => setIsDark((d) => !d)}
      aria-label={isDark ? 'Włącz tryb jasny' : 'Włącz tryb ciemny'}
    >
      {isDark ? <Sun className="size-5" /> : <Moon className="size-5" />}
    </Button>
  );
}
