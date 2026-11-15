import type { CSSProperties } from 'react';
import { sanitizeFileName, splitFinalExtension } from '../attachments/sanitize';

/** Code points kept visible at the end of a clipped name without a final extension (REQ-23). */
const TAIL_CODE_POINTS = 16;

export const NAME_CHANGED_TOOLTIP = 'Name contained characters that were removed';

const rootStyle: CSSProperties = {
  display: 'inline-flex',
  maxWidth: '100%',
  minWidth: 0,
  whiteSpace: 'nowrap',
  unicodeBidi: 'isolate',
};
const clipStyle: CSSProperties = {
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
  minWidth: 0,
  flexShrink: 1,
};
const keepStyle: CSSProperties = {
  whiteSpace: 'nowrap',
  flexShrink: 0,
};

/**
 * A sender-chosen file name, sanitized (REQ-23) and rendered as text only.
 * The stem sits in its own bidi isolate (`dir="auto"`) and may be clipped with
 * an ellipsis; the final extension sits in a separate left-to-right isolate
 * that is never clipped, so neither a bidi override nor clipping can hide
 * `.exe`. A name without a final extension keeps its last 16 code points
 * visible.
 */
export function AttachmentName({ name, className }: { name: string; className?: string }) {
  const sanitized = sanitizeFileName(name);
  const { stem, ext } = splitFinalExtension(sanitized.name);
  const title = sanitized.changed ? NAME_CHANGED_TOOLTIP : undefined;
  if (ext !== '') {
    return (
      <span className={className ? `attachment-name ${className}` : 'attachment-name'} style={rootStyle} title={title} data-testid="attachment-name">
        <bdi dir="auto" className="attachment-name-stem" style={clipStyle}>{stem}</bdi>
        <bdi dir="ltr" className="attachment-name-ext" style={keepStyle}>{ext}</bdi>
      </span>
    );
  }
  const cps = Array.from(stem);
  const head = cps.slice(0, Math.max(0, cps.length - TAIL_CODE_POINTS)).join('');
  const tail = cps.slice(Math.max(0, cps.length - TAIL_CODE_POINTS)).join('');
  return (
    <span className={className ? `attachment-name ${className}` : 'attachment-name'} style={rootStyle} title={title} data-testid="attachment-name">
      <bdi dir="auto" className="attachment-name-stem" style={{ ...rootStyle, ...clipStyle }}>
        <span className="attachment-name-head" style={clipStyle}>{head}</span>
        <span className="attachment-name-tail" style={keepStyle}>{tail}</span>
      </bdi>
    </span>
  );
}

export default AttachmentName;
