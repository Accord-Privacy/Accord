/**
 * @module attachments/messageFields
 * The `Message` fields that the decode function and the pending-send records
 * decide (SPEC-02 REQ-8, REQ-11, §8.1, §8.2). `content` is the decoded body or
 * a placeholder text, never a descriptor; attachment state stays in the store
 * and a `Message` carries at most its count.
 */

import type { Message } from '../types';
import { PLACEHOLDER_TEXT, type DecodedMessage } from './decode';
import type { PendingView } from './send';

/** The status fields of an own pending send's temporary message (§8.1). */
export function pendingStatusFields(view: PendingView): Pick<Message, '_status' | '_statusText' | '_failure'> {
  return {
    _status: view.status,
    _statusText: view.statusText ?? undefined,
    _failure: view.failure ? { text: view.failure.text, retryable: view.failure.retryable } : undefined,
  };
}

/** The `Message` fields the decode function decides (SPEC-02 REQ-8, REQ-11). */
export function decodedFields(d: DecodedMessage, isDm: boolean): Pick<Message, 'content' | 'isEncrypted' | 'e2eeType' | '_placeholder' | '_attachmentsIgnored' | '_attachmentCount' | '_attachmentRef'> {
  const channelType = isDm ? 'double-ratchet' as const : 'sender-keys' as const;
  let e2eeType: NonNullable<Message['e2eeType']> = 'none';
  if (d.source === 'dr') e2eeType = 'double-ratchet';
  else if (d.source === 'sk') e2eeType = 'sender-keys';
  else if (d.source === 'cache') e2eeType = d.cacheSource === 'dr' ? 'double-ratchet' : d.cacheSource === 'sk' ? 'sender-keys' : channelType;
  else if (d.source === 'legacy_cache') e2eeType = channelType;
  else if (d.source === 'legacy_key') e2eeType = 'symmetric';
  const isEncrypted = e2eeType !== 'none';
  return {
    content: d.display === 'placeholder' && d.placeholder ? PLACEHOLDER_TEXT[d.placeholder] : d.body,
    isEncrypted,
    e2eeType,
    _placeholder: d.placeholder ?? undefined,
    _attachmentsIgnored: d.attachmentsIgnored || undefined,
    // Both keys are always present, so spreading these fields over an earlier
    // version of the message (a paired send) clears what that version had.
    _attachmentCount: d.attachmentCount > 0 && d.attachmentRef !== null ? d.attachmentCount : undefined,
    _attachmentRef: d.attachmentCount > 0 && d.attachmentRef !== null ? d.attachmentRef : undefined,
  };
}

