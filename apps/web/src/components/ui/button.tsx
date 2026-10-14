import { cva, type VariantProps } from "class-variance-authority";
import type { ButtonHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

const button = cva(
  "inline-flex items-center justify-center gap-1.5 whitespace-nowrap transition-colors disabled:pointer-events-none",
  {
    variants: {
      variant: {
        solid: "bg-text text-ground hover:bg-accent",
        outline: "border border-border text-text hover:border-accent hover:text-accent",
        ghost: "text-muted hover:text-text",
        danger: "border border-critical/60 text-critical hover:bg-critical hover:text-ground",
      },
      size: {
        sm: "h-6 px-2 text-2xs",
        md: "h-7 px-3 text-xs",
        lg: "h-9 px-4 text-sm",
      },
    },
    defaultVariants: { variant: "outline", size: "md" },
  },
);

export interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof button> {}

export function Button({ className, variant, size, type = "button", ...props }: ButtonProps) {
  return <button type={type} className={cn(button({ variant, size }), className)} {...props} />;
}
