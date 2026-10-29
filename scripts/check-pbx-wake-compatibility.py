#!/usr/bin/env python3
"""Read an effective macro-dial-one CLI listing and fail closed for wake.

This diagnostic recognizes one observed ordering only; it is NOT a validator
for a dialplan patch. No layout is currently approved for automatic activation.
It never invokes Asterisk, edits files, prints dialplan text or reads secrets.
"""
import json
import sys

MAX_INPUT = 256 * 1024


def main():
    data = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        reason = 'input_too_large'
    else:
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError:
            text = ''
        # The listing is deliberately only classified, never approved. Checking
        # snippets alone cannot establish control flow, hook ownership or safety.
        ordered = [
            "'s' =>",
            'Set(DEXTEN=${ARG3})',
            'DB(CF/${DEXTEN})',
            'DB(DND/${DEXTEN})',
            'DB(CFU/${DEXTEN})',
            '?dstring,1():dlocal,1()',
            'LEN(${DSTRING})',
            'Dial(${DSTRING},${ARG1}',
        ]
        offset = 0
        for part in ordered:
            position = text.find(part, offset)
            if position < 0:
                break
            offset = position + len(part)
        else:
            position = 0
        observed = ("[ Context 'macro-dial-one'" in text
                    and 'PJSIP_DIAL_CONTACTS(${PJ})' in text
                    and position == 0)
        reason = 'mobile_companion_not_validated' if observed else 'unrecognized_dialplan'
    print(json.dumps({'wakeReady': False, 'compatibility': 'unsupported', 'reason': reason},
                     sort_keys=True))
    return 2


if __name__ == '__main__':
    sys.exit(main())
