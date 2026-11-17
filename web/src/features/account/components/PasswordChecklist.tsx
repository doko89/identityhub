import { Check } from "lucide-react";
import { cn } from "cn";

// passwordRules mirrors domain.CheckPasswordComplexity on the server:
// each rule reports whether the candidate satisfies it. The server
// stays the source of truth; this only previews the outcome live.
export interface PasswordRule {
  label: string;
  met: boolean;
}

export function passwordRules(value: string): PasswordRule[] {
  const chars = [...value];
  return [
    { label: "8 characters", met: chars.length >= 8 },
    { label: "Uppercase letter", met: chars.some((ch) => /\p{Lu}/u.test(ch)) },
    { label: "Symbol", met: chars.some((ch) => /[^\p{L}\p{Nd}]/u.test(ch)) },
  ];
}

// PasswordChecklist previews the three password rules under a
// new-password field, updating as the user types. Unmet rows stay
// muted (never red errors) so the form feels guiding, not scolding.
export function PasswordChecklist({ value }: { value: string }) {
  return (
    <ul className="flex flex-col gap-1" aria-label="Password requirements">
      {passwordRules(value).map((rule) => (
        <li
          key={rule.label}
          data-met={rule.met}
          className={cn(
            "flex items-center gap-2 text-xs",
            rule.met ? "text-primary" : "text-muted-foreground",
          )}
        >
          <Check className="size-3.5" aria-hidden="true" />
          <span>{rule.label}</span>
        </li>
      ))}
    </ul>
  );
}
