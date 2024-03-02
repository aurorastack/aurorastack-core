from aurorastack.core.locator import Locator
from aurorastack.core.transaction import Transaction, get_transaction


class CoreObject(object):

    def __init__(self, *args, **kwargs):
        self.locator = Locator()
        get_transaction()

    @property
    def transaction(self) -> Transaction:
        return get_transaction()
