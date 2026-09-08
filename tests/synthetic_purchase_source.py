"""Test-only reviewed source. Constants are independent of browser text.

This is not a production adapter, public observation service, or evidence of
merchant terms. Tests use an intercepted disposable site and invented catalog.
No test copies arbitrary DOM strings into the production source registry.
"""
from copy import deepcopy
from plugin.purchase_approval import validate_source_contract

_CONTRACT = {
    'version': 1, 'item': 'Example subscription', 'merchant': 'Example merchant',
    'currency': 'USD',
    'price': {'subtotal': 1000, 'tax': 100, 'fees': 134, 'total': 1234},
    'refund': 'non_refundable',
    'recurrence': {
        'kind': 'recurring', 'first_start': '2026-09-08',
        'first_end': '2027-09-08', 'renewal_start': '2027-09-08',
        'cadence': 'annually',
        'price': {'subtotal': 1800, 'tax': 200, 'fees': 0, 'total': 2000},
    },
}


def contract():
    return deepcopy(_CONTRACT)


SUMMARY = validate_source_contract(contract())
