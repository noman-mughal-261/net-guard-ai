import { useState, type InputHTMLAttributes } from "react";

type PasswordInputProps = Omit<InputHTMLAttributes<HTMLInputElement>, "type">;

export function PasswordInput({ className = "", ...props }: PasswordInputProps) {
  const [visible, setVisible] = useState(false);

  return (
    <div className={`relative ${className}`}>
      <input {...props} type={visible ? "text" : "password"} className="ng-input pr-16" />
      <button
        type="button"
        onClick={() => setVisible((value) => !value)}
        aria-label={visible ? "Hide password" : "Show password"}
        aria-pressed={visible}
        className="absolute right-3 top-1/2 -translate-y-1/2 rounded px-1 py-1 text-xs font-medium"
        style={{ color: "var(--ng-muted)" }}
      >
        {visible ? "Hide" : "Show"}
      </button>
    </div>
  );
}
