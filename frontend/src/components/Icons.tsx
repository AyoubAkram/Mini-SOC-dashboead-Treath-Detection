import React from 'react';

// Small inline icons (24x24 stroke icons), so the UI needs no icon library.
const paths: Record<string, React.ReactNode> = {
  overview: <><rect x="3" y="3" width="7" height="9" rx="1.5" /><rect x="14" y="3" width="7" height="5" rx="1.5" /><rect x="14" y="12" width="7" height="9" rx="1.5" /><rect x="3" y="16" width="7" height="5" rx="1.5" /></>,
  alerts: <><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9" /><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0" /></>,
  search: <><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></>,
  entities: <><circle cx="9" cy="8" r="3.5" /><path d="M2.5 20a6.5 6.5 0 0 1 13 0" /><path d="M16 4.6a3.5 3.5 0 0 1 0 6.8" /><path d="M18 14.5a6.5 6.5 0 0 1 3.5 5.5" /></>,
  shield: <><path d="M12 3 4.5 6v5.5c0 4.6 3.1 8 7.5 9.5 4.4-1.5 7.5-4.9 7.5-9.5V6L12 3Z" /><path d="m9 12 2 2 4-4.5" /></>,
  refresh: <><path d="M20 11a8 8 0 0 0-14.3-4.3L4 8.5" /><path d="M4 4v4.5h4.5" /><path d="M4 13a8 8 0 0 0 14.3 4.3L20 15.5" /><path d="M20 20v-4.5h-4.5" /></>,
  check: <path d="m5 12.5 4.5 4.5L19 7.5" />,
  eye: <><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z" /><circle cx="12" cy="12" r="3" /></>,
  undo: <><path d="M9 14 4 9l5-5" /><path d="M4 9h10.5a5.5 5.5 0 0 1 0 11H11" /></>,
  close: <><path d="M6 6l12 12" /><path d="M18 6 6 18" /></>,
  download: <><path d="M12 4v11" /><path d="m7.5 11 4.5 4.5 4.5-4.5" /><path d="M5 20h14" /></>,
  cpu: <><rect x="6" y="6" width="12" height="12" rx="2" /><rect x="10" y="10" width="4" height="4" /><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4" /></>,
  link: <><circle cx="6" cy="12" r="2.5" /><circle cx="18" cy="6" r="2.5" /><circle cx="18" cy="18" r="2.5" /><path d="m8.2 10.9 7.6-3.8M8.2 13.1l7.6 3.8" /></>,
  chevron: <path d="m9 6 6 6-6 6" />
};

interface IconProps {
  name: keyof typeof paths | string;
  size?: number;
}

const Icon = ({ name, size = 18 }: IconProps) => (
  <svg
    className="icon"
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    {paths[name]}
  </svg>
);

export default Icon;
