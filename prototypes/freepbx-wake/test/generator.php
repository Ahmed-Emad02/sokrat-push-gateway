<?php
// Runs in a clean PHP process once per upstream generator version.
define('FREEPBX_IS_AUTH', true);
error_reporting(E_ALL & ~E_DEPRECATED);
class FakeConfig { function get($key) { return ''; } }
class FreePBX { static function Config() { return new FakeConfig(); } }
$amp_conf = ['NOOPTRACE' => '0'];
$chan_dahdi = false;
$version = $argv[1];
$root = dirname(__DIR__);
require $root . '/fixtures/upstream/' . ($version === '17' ? 'extensions17.class.php' : 'extensions.class.php');
require $root . '/fixtures/upstream/macroDialone' . $version . '.php';
require $root . '/module/functions.inc.php';

function check($condition, $message) {
    if (!$condition) { fwrite(STDERR, "FAIL: $message\n"); exit(1); }
}
function build() {
    $ext = new extensions();
    \FreePBX\modules\Core\Dialplan\macroDialone::add($ext);
    return $ext;
}
$ext = build();
$before = $ext->generateConf();
check(sokratwake_insert($ext, 'asterisk', $version . '.0.1'), 'supported layout inserts');
$after = $ext->generateConf();
$snippet = 'GosubIf($["${DEXTEN:-1}"!="#"]?dstring,1():dlocal,1())';
$empty = 'GotoIf($[${LEN(${DSTRING})}=0]?nodial)';
$wake = '?sub-sokrat-wake-prepare,s,1';
check(substr_count($after, $wake) === 1, 'exactly one hook');
check(preg_replace('/^exten => s,n,GosubIf\(.*sub-sokrat-wake-prepare.*\)\R/m', '', $after) === $before, 'only the intended instruction changed');
check(strpos($after, $snippet) < strpos($after, $wake) && strpos($after, $wake) < strpos($after, $empty), 'hook is between resolution and empty exit');
check(strpos($after, 'DB(DND/${DEXTEN})') < strpos($after, $wake), 'DND before hook');
check(strpos($after, 'DB(CF/${DEXTEN})') < strpos($after, $wake), 'forwarding before hook');
check(!sokratwake_insert($ext, 'asterisk', $version . '.0.1'), 'repeat cannot duplicate');
check($ext->generateConf() === $after, 'repeat leaves generated content unchanged');
$fresh = build();
check(sokratwake_insert($fresh, 'asterisk', $version . '.0.1'), 'regeneration inserts again');
check($fresh->generateConf() === $after, 'regeneration deterministic');
$unsupported = build();
check(!sokratwake_insert($unsupported, 'asterisk', '18.0'), 'unknown version refused');
check($unsupported->generateConf() === $before, 'unknown version unchanged');
$mutated = build();
$mutated->_exts['macro-dial-one'][' s '][0]['tag'] = 'continue';
// A duplicate branch label changes the layout and must not be accepted.
check(!sokratwake_insert($mutated, 'asterisk', $version . '.0.1'), 'duplicate continue label refused');
$mutated = build();
$mutated->_exts['macro-dial-one'][' s '][5]['cmd'] = new ext_noop('DND bypass');
$original = $mutated->generateConf();
check(!sokratwake_insert($mutated, 'asterisk', $version . '.0.1'), 'changed policy refused');
check($original === $mutated->generateConf(), 'changed policy left untouched');
$mutated = build();
$mutated->_exts['macro-dial-one'][' dstring '][0]['cmd'] = new ext_noop('changed lookup');
$original = $mutated->generateConf();
check(!sokratwake_insert($mutated, 'asterisk', $version . '.0.1'), 'changed contact lookup refused');
check($original === $mutated->generateConf(), 'changed lookup left untouched');
$chan_dahdi = true;
$dahdi = build();
check(sokratwake_insert($dahdi, 'asterisk', $version . '.0.1'), 'known DAHDI layout inserts');
echo "FreePBX $version generator tests passed\n";
