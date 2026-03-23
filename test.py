import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from Bank import (
    Account,
    Transaction,
    ClientDevice,
    Bank,
    EntityID
)

# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def alice():
    return ClientDevice.generate()

@pytest.fixture
def bob():
    return ClientDevice.generate()

@pytest.fixture
def bank():
    return Bank()

@pytest.fixture
def alice_id(bank, alice):
    return bank.create_account(alice.get_public_key())

@pytest.fixture
def bob_id(bank, bob):
    return bank.create_account(bob.get_public_key())

@pytest.fixture
def funded_bank(bank, alice, bob):
    """Bank с Alice=1000, Bob=200."""
    a_id = bank.create_account(alice.get_public_key())
    b_id = bank.create_account(bob.get_public_key())
    
    # Доступ к объектам через внутреннее хранилище банка для тестов
    bank._accounts[a_id]._balance = 1000
    bank._accounts[b_id]._balance = 200
    return bank, a_id, b_id

def _sign_both(bank, tx, sender_device, sender_id, receiver_device, receiver_id):
    tx.add_signature(sender_id, sender_device.sign_transaction(tx.canonical_data))
    tx.add_signature(receiver_id, receiver_device.sign_transaction(tx.canonical_data))


# ─── ClientDevice ─────────────────────────────────────────────────────────────

class TestClientDevice:
    def test_generate_returns_device(self):
        device = ClientDevice.generate()
        assert isinstance(device, ClientDevice)

    def test_accounts_default_empty(self):
        d1 = ClientDevice.generate()
        d2 = ClientDevice.generate()
        d1.accounts.append(EntityID("ACC-TEST"))
        assert d2.accounts == []


# ─── Account ──────────────────────────────────────────────────────────────────

class TestAccount:
    def test_prefix(self, bank, alice_id):
        assert alice_id.startswith("ACC-")
        assert isinstance(bank._accounts[alice_id], Account)

    def test_public_key_stored(self, bank, alice, alice_id):
        acc = bank._accounts[alice_id]
        assert acc.public_key is alice.get_public_key()


# ─── Transaction ──────────────────────────────────────────────────────────────

class TestTransaction:
    def test_canonical_data_format(self, alice_id, bob_id):
        tx = Transaction(_sender_id=alice_id, _receiver_id=bob_id, _amount=50)
        parts = tx.canonical_data.split(":")
        assert parts[1] == alice_id
        assert parts[2] == bob_id
        assert parts[3] == "50"

    def test_add_signature(self, alice, alice_id, bob_id):
        tx = Transaction(_sender_id=alice_id, _receiver_id=bob_id, _amount=100)
        sig = alice.sign_transaction(tx.canonical_data)
        tx.add_signature(alice_id, sig)
        assert alice_id in tx._signatures


# ─── Bank.create_account ──────────────────────────────────────────────────────

class TestBankCreateAccount:
    def test_returns_entity_id(self, bank, alice):
        acc_id = bank.create_account(alice.get_public_key())
        assert isinstance(acc_id, str) # EntityID это NewType от str
        assert acc_id in bank._accounts

    def test_rejects_non_rsa_key(self, bank):
        with pytest.raises(TypeError):
            bank.create_account("not-a-key")


# ─── Bank.execute_transaction ─────────────────────────────────────────────────

class TestExecuteTransaction:
    def test_happy_path_balances(self, funded_bank, alice, bob):
        bank, a_id, b_id = funded_bank
        tx = bank.init_transaction(a_id, b_id, 300)
        _sign_both(bank, tx, alice, a_id, bob, b_id)

        result = bank.execute_transaction(tx)

        assert result is True
        assert bank._accounts[a_id].balance == 700
        assert bank._accounts[b_id].balance == 500

    def test_insufficient_funds_returns_false(self, funded_bank, alice, bob):
        bank, a_id, b_id = funded_bank
        tx = bank.init_transaction(a_id, b_id, 9999)
        _sign_both(bank, tx, alice, a_id, bob, b_id)
        result = bank.execute_transaction(tx)
        assert result is False
        assert bank._accounts[a_id].balance == 1000


# ─── Bank.verify_ownership ────────────────────────────────────────────────────

class TestVerifyOwnership:
    def test_correct_owner_returns_true(self, bank, alice, alice_id):
        assert bank.verify_ownership(alice_id, alice.get_public_key_pem()) is True

    def test_wrong_device_returns_false(self, bank, bob, alice_id):
        assert bank.verify_ownership(alice_id, bob.get_public_key_pem()) is False


# ─── Bank._change_balance ─────────────────────────────────────────────────────

class TestChangeBalance:
    def test_balance_cannot_go_negative(self, bank, alice_id):
        acc = bank._accounts[alice_id]
        acc._balance = 100
        result = bank._change_balance(acc, -200)
        assert result is False
        assert acc.balance == 100