import importlib.util
import io
import pathlib
import unittest

path = pathlib.Path(__file__).resolve().parents[1] / 'runtime' / 'sokrat-wake-agi.py'
spec = importlib.util.spec_from_file_location('wake_agi', path)
wake = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wake)

DESKTOP = 'PJSIP/employee/sip:desktop@example.test:5060'
MOBILE = 'PJSIP/employee/sip:mobile@example.test:5060;transport=ws'
CRM = 'PJSIP/employee/sip:crm@example.test:5060;transport=ws'


class FakeAGI:
    def __init__(self, baseline=DESKTOP, contacts=''):
        self.values = {'SOKRAT_WAKE_BASELINE': baseline, 'SOKRAT_WAKE_ENDPOINT': 'employee'}
        self.live = contacts
    def get(self, key): return self.values.get(key, '')
    def contacts(self, endpoint): return self.live
    def set(self, key, value): self.values[key] = value


class TestWake(unittest.TestCase):
    def test_selection_uses_attested_new_contact_only(self):
        current = '&'.join([DESKTOP, CRM, MOBILE])
        self.assertEqual(wake.choose_contact('employee', MOBILE, current, DESKTOP), MOBILE)
        self.assertEqual(wake.choose_contact('employee', DESKTOP, current, DESKTOP), '')
        self.assertEqual(wake.choose_contact('employee', MOBILE, DESKTOP, DESKTOP), '')
        self.assertEqual(wake.choose_contact('other', MOBILE, current, ''), '')
        self.assertEqual(wake.choose_contact('employee', MOBILE + '&' + CRM, current, ''), '')
        self.assertEqual(wake.choose_contact('employee', MOBILE + ',Hangup()', current, ''), '')

    def test_prepare_requires_explicit_eligibility_and_endpoint(self):
        agi = FakeAGI()
        wake.run(agi, 'prepare', '123', lambda _: {'eligible': True, 'endpoint': 'employee'})
        self.assertEqual(agi.values['SOKRAT_WAKE_ARMED'], '1')
        for response in ({'eligible': False, 'endpoint': 'employee'},
                         {'eligible': True, 'endpoint': 'employee&other'}, {}):
            agi = FakeAGI()
            wake.run(agi, 'prepare', '123', lambda _: response)
            self.assertNotIn('SOKRAT_WAKE_ARMED', agi.values)

    def test_wait_never_selects_existing_or_unattested_crm(self):
        agi = FakeAGI(contacts='&'.join([DESKTOP, CRM, MOBILE]))
        def identity(request):
            self.assertEqual(request['contacts'], [DESKTOP, CRM, MOBILE])
            return {'eligible': True, 'endpoint': 'employee', 'contact': MOBILE}
        wake.run(agi, 'wait', '123', identity)
        self.assertEqual(agi.values['SOKRAT_WAKE_CONTACT'], MOBILE)
        agi = FakeAGI(baseline=MOBILE, contacts=MOBILE)
        ticks = iter([0, 0, 9])
        wake.run(agi, 'wait', '123', lambda _: {'eligible': True, 'endpoint': 'employee', 'contact': MOBILE},
                 lambda: next(ticks), lambda _: None)
        self.assertNotIn('SOKRAT_WAKE_CONTACT', agi.values)

    def test_denial_or_invalid_extension_never_dials(self):
        agi = FakeAGI(contacts=MOBILE)
        wake.run(agi, 'wait', '123', lambda _: {'eligible': False, 'endpoint': 'employee', 'contact': MOBILE})
        self.assertNotIn('SOKRAT_WAKE_CONTACT', agi.values)
        wake.run(agi, 'prepare', '123&other', lambda _: self.fail('unexpected request'))

    def test_registration_after_poll_selects_only_attested_mobile(self):
        agi = FakeAGI(contacts=DESKTOP)
        attempts = []
        def identity(request):
            attempts.append(request)
            if len(attempts) == 1:
                agi.live = '&'.join([DESKTOP, CRM, MOBILE])
                return {'eligible': True, 'endpoint': 'employee', 'contact': ''}
            return {'eligible': True, 'endpoint': 'employee', 'contact': MOBILE}
        wake.run(agi, 'wait', '123', identity, sleep=lambda _: None)
        self.assertEqual(len(attempts), 2)
        self.assertEqual(agi.values['SOKRAT_WAKE_CONTACT'], MOBILE)

    def test_socket_under_writable_directory_is_rejected(self):
        with self.assertRaises(ValueError):
            wake.trusted_socket('/tmp/does-not-matter/identity.sock')

    def test_agi_prepare_emits_only_validated_values(self):
        source = io.StringIO('agi_channel: Local/test\n\n200 result=1\n200 result=1\n')
        output = io.StringIO()
        agi = wake.AGI(source, output)
        wake.run(agi, 'prepare', '123', lambda _: {'eligible': True, 'endpoint': 'employee'})
        self.assertEqual(output.getvalue(), 'SET VARIABLE SOKRAT_WAKE_ENDPOINT "employee"\n'
                                            'SET VARIABLE SOKRAT_WAKE_ARMED "1"\n')

    def test_agi_protocol_and_injection_rejection(self):
        input_data = io.StringIO('agi_channel: Local/test\n\n200 result=1 (ok)\n')
        output = io.StringIO()
        agi = wake.AGI(input_data, output)
        self.assertEqual(agi.get('SOKRAT_WAKE_ENDPOINT'), 'ok')
        self.assertEqual(output.getvalue(), 'GET VARIABLE SOKRAT_WAKE_ENDPOINT\n')
        with self.assertRaises(ValueError): agi.command('GET VARIABLE x\nHANGUP')


if __name__ == '__main__':
    unittest.main()
