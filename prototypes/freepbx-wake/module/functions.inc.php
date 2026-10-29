<?php
// A generation-time prototype. No installer is provided or implied.
if (!defined('FREEPBX_IS_AUTH')) { die('No direct script access allowed'); }

/** Insert after dstring/dlocal resolution, before the empty-DSTRING exit.
 * Unknown layouts are deliberately left byte-for-byte unchanged.
 */
function sokratwake_insert($ext, $engine, $freepbxVersion) {
    if ($engine !== 'asterisk' || !preg_match('/^(16|17)\./', (string) $freepbxVersion)) {
        return false;
    }
    if (!is_object($ext) || !method_exists($ext, 'splice') ||
        !isset($ext->_exts['macro-dial-one'][' s '], $ext->_exts['macro-dial-one'][' dstring '])) {
        return false;
    }
    $entries = $ext->_exts['macro-dial-one'][' s '];
    $dstring = $ext->_exts['macro-dial-one'][' dstring '];
    $outputs = array_map(function ($entry) { return $entry['cmd']->output(); }, $entries);
    $doutputs = array_map(function ($entry) { return $entry['cmd']->output(); }, $dstring);
    $needle = 'GosubIf($["${DEXTEN:-1}"!="#"]?dstring,1():dlocal,1())';
    $empty = 'GotoIf($[${LEN(${DSTRING})}=0]?nodial)';
    $continue = 'GotoIf($["${DEXTEN}"=""]?nodial)';
    $positions = array_keys($outputs, $needle, true);
    if (count($positions) !== 1) { return false; }
    $i = $positions[0];
    $continueLabels = array_keys(array_column($entries, 'tag'), 'continue', true);
    if ($i < 1 || !isset($outputs[$i + 1]) || $outputs[$i - 1] !== $continue ||
        $continueLabels !== [$i - 1] || $entries[$i + 1]['tag'] !== '' || $outputs[$i + 1] !== $empty ||
        !in_array('GosubIf($["${DB(CF/${DEXTEN})}"!=""]?cf,1())', $outputs, true) ||
        !in_array('GotoIf($["${DEXTEN:-1}"="#" | "${DB(DND/${DEXTEN})}"=""]?skip1)', $outputs, true) ||
        !in_array('Set(THISDIAL=${PJSIP_DIAL_CONTACTS(${THISDIAL:6})})', $doutputs, true)) {
        return false;
    }
    // Verify forwarding and DND precede the insertion, rather than just existing.
    $cf = array_search('GosubIf($["${DB(CF/${DEXTEN})}"!=""]?cf,1())', $outputs, true);
    $dnd = array_search('GotoIf($["${DEXTEN:-1}"="#" | "${DB(DND/${DEXTEN})}"=""]?skip1)', $outputs, true);
    if ($cf >= $i || $dnd >= $i) { return false; }
    // Pin the complete policy prefix and dstring routine, not just a few anchors.
    // This rejects customer forks and future core changes until reviewed.
    $fingerprint = function ($rows) {
        $items = array_map(function ($row) { return [$row['tag'], $row['cmd']->output()]; }, $rows);
        return hash('sha256', json_encode($items));
    };
    if ($fingerprint(array_slice($entries, 0, $i + 1)) !== 'b7ad9d1657624f79c1d75862bb9fe0484e45bb5aeeaa9bc78b9b7e164dced087' ||
        !in_array($fingerprint($dstring), [
            '21a9bb2e8fef5116da99d171e133c804474d64bddc660af2f9edfb1dd2bb9265',
            '0c43bd9813964ca26f44d1879309252f967ac25b2226eb85c48dc56d5844811b'
        ], true)) { return false; }
    $guard = '$["${DEXTEN:-1}"!="#" & ${REGEX("^[0-9]+$" ${DEXTEN})} = 1 & "${DB(SOKRAT_WAKE/${DEXTEN}/enabled)}"="1" & ${DIALPLAN_EXISTS(sub-sokrat-wake-prepare,s,1)} = 1 & ${DIALPLAN_EXISTS(sub-sokrat-push-send,s,1)} = 1]';
    $command = new \ext_gosubif($guard, 'sub-sokrat-wake-prepare,s,1', false, '${DEXTEN}');
    // splice() uses a zero-based numeric array index, not a dialplan priority.
    // Inserting immediately after the dstring instruction preserves the label
    // on the empty-DSTRING check and all pre-existing instructions.
    $ext->splice('macro-dial-one', 's', $i + 1, $command);
    return true;
}

function sokratwake_hookGet_config($engine) {
    global $ext;
    return sokratwake_insert($ext, $engine, function_exists('getversion') ? getversion() : '');
}
