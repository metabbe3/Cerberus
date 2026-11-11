export function CerberusMark({
  size = 36,
  className,
}: {
  size?: number;
  className?: string;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      role="img"
      aria-label="Cerberus"
    >
      {/* Tiga kepala */}
      <circle cx="14" cy="21" r="7.5" fill="currentColor" />
      <circle cx="24" cy="17.5" r="8" fill="currentColor" />
      <circle cx="34" cy="21" r="7.5" fill="currentColor" />
      {/* Telinga tengah */}
      <path d="M22 10.2 L24 4.5 L26 10.2 Z" fill="currentColor" />
      {/* Badan */}
      <path
        d="M8.5 40 V33 C8.5 28.5 12 25 16.5 25 H31.5 C36 25 39.5 28.5 39.5 33 V40 Q39.5 41.5 38 41.5 H10 Q8.5 41.5 8.5 40 Z"
        fill="currentColor"
      />
      {/* Mata */}
      <circle cx="13" cy="20.5" r="1.4" fill="var(--clay-coral-soft, #FFD9CC)" />
      <circle cx="24" cy="17" r="1.4" fill="var(--clay-coral-soft, #FFD9CC)" />
      <circle cx="35" cy="20.5" r="1.4" fill="var(--clay-coral-soft, #FFD9CC)" />
    </svg>
  );
}
