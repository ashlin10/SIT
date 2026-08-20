# Frontend Styling Guidelines

## Dropdown / Select Elements

All `<select>` elements **must** use the shared `selectCls` class from `@/lib/utils`.

```tsx
import { selectCls } from '@/lib/utils'

<select className={selectCls}>
  <option value="">Select...</option>
</select>

// With additional classes:
<select className={cn(selectCls, 'w-full')}>
```

**Do NOT** define local `selectCls` constants or use `inputCls` on `<select>` elements.

The `selectCls` provides:
- Consistent padding, border radius, and font size
- Light/dark mode colors
- Focus ring styling
- Custom dropdown arrow via embedded SVG
- Disabled opacity and transition

## Page Navigation Animation

Every top-level page component must use the `fadeIn` animation on its root `<div>`:

```tsx
<div className="space-y-5 animate-[fadeIn_0.3s_ease-out]">
```

The `fadeIn` keyframe is defined globally in `index.css`.

## Input Elements

Use `inputCls` from `@/lib/utils` for all text `<input>` elements.

## Buttons

Use `btnCls()` and `iconBtnCls()` from `@/lib/utils` for all buttons.
