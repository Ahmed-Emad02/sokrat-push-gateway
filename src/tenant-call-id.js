'use strict';

// Push and SIP's application correlation header must use the same tenant scope.
// The SIP protocol Call-ID is deliberately untouched.
function tenantCallId(normalizeCallId, pbxId, callId) {
    if (typeof callId !== 'string' || !callId || callId.length > 96) throw new Error('Invalid callId');
    return normalizeCallId(`${pbxId}:${callId}`);
}

module.exports = { tenantCallId };
