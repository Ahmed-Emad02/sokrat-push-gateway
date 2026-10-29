"""Illustrative counterexamples, not an Asterisk or identity-service test."""
import unittest


def registrar_model(existing, uri, request_call_id):
    """Model only the observed 18.19 create/refresh Call-ID distinction."""
    if uri not in existing:
        existing[uri] = {'call_id': request_call_id, 'refreshes': 0}
    else:
        existing[uri]['refreshes'] += 1  # Asterisk copies the original call_id.


class Counterexamples(unittest.TestCase):
    def test_stored_call_id_does_not_prove_current_registrar(self):
        contacts = {}
        registrar_model(contacts, 'synthetic-uri', 'mobile-transaction')
        registrar_model(contacts, 'synthetic-uri', 'other-transaction')
        self.assertEqual(contacts['synthetic-uri']['call_id'], 'mobile-transaction')
        self.assertEqual(contacts['synthetic-uri']['refreshes'], 1)

    def test_snapshot_can_become_stale_before_dial(self):
        contact_owner = {'synthetic-uri': 'mobile'}
        selected = next(uri for uri, owner in contact_owner.items() if owner == 'mobile')
        contact_owner[selected] = 'other-client'  # registration changed after selection
        self.assertEqual(contact_owner[selected], 'other-client')


if __name__ == '__main__':
    unittest.main()
