import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from Bank import (
    Account,
    Transaction,
    ClientDevice,
    Bank,
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
def alice_acc(bank, alice):
    return bank.create_account(alice.get_public_key())

@pytest.fixture
def bob_acc(bank, bob):
    return bank.create_account(bob.get_public_key())

@pytest.fixture
def funded_bank(bank, alice, bob):
    """Bank с Alice=1000, Bob=200."""
    alice_acc = bank.create_account(alice.get_public_key())
    bob_acc   = bank.create_account(bob.get_public_key())
    alice_acc._balance = 1000
    bob_acc._balance   = 200
    return bank, alice_acc, bob_acc

def _sign_both(tx, sender_device, sender_acc, receiver_device, receiver_acc):
    tx.add_signature(sender_acc.id,   sender_device.sign_transaction(tx.canonical_data))
    tx.add_signature(receiver_acc.id, receiver_device.sign_transaction(tx.canonical_data))


# ─── ClientDevice ─────────────────────────────────────────────────────────────

class TestClientDevice:
    def test_generate_returns_device(self):
        device = ClientDevice.generate()
        assert isinstance(device, ClientDevice)

    def test_public_key_matches_private(self):
        device = ClientDevice.generate()
        assert device.get_public_key() is device.public_key

    def test_get_public_key_pem_is_bytes(self, alice):
        pem = alice.get_public_key_pem()
        assert isinstance(pem, bytes)
        assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")

    def test_sign_returns_bytes(self, alice):
        sig = alice.sign_transaction("some:data:here:100")
        assert isinstance(sig, bytes)
        assert len(sig) > 0

    def test_sign_requires_str(self, alice):
        with pytest.raises(TypeError):
            alice.sign_transaction(12345)

    def test_accounts_default_empty(self):
        d1 = ClientDevice.generate()
        d2 = ClientDevice.generate()
        d1.accounts.append("ACC-00000001")
        # mutable default guard: d2 должен быть пустым
        assert d2.accounts == []

    def test_different_devices_produce_different_keys(self):
        d1 = ClientDevice.generate()
        d2 = ClientDevice.generate()
        assert d1.get_public_key_pem() != d2.get_public_key_pem()


# ─── Account ──────────────────────────────────────────────────────────────────

class TestAccount:
    def test_prefix(self, alice_acc):
        assert alice_acc.id.startswith("ACC-")

    def test_default_balance(self, alice_acc):
        assert alice_acc.balance == 0

    def test_balance_property_readonly(self, alice_acc):
        with pytest.raises(AttributeError):
            alice_acc.balance = 999

    def test_public_key_stored(self, alice, alice_acc):
        assert alice_acc.public_key is alice.get_public_key()


# ─── Transaction ──────────────────────────────────────────────────────────────

class TestTransaction:
    def test_prefix(self, alice_acc, bob_acc):
        tx = Transaction(_sender_id=alice_acc.id, _receiver_id=bob_acc.id, _amount=100)
        assert tx.id.startswith("TRN-")

    def test_default_status_pending(self, alice_acc, bob_acc):
        tx = Transaction(_sender_id=alice_acc.id, _receiver_id=bob_acc.id, _amount=100)
        assert tx._status == "PENDING"

    def test_canonical_data_format(self, alice_acc, bob_acc):
        tx = Transaction(_sender_id=alice_acc.id, _receiver_id=bob_acc.id, _amount=50)
        parts = tx.canonical_data.split(":")
        assert len(parts) == 4
        assert parts[1] == alice_acc.id
        assert parts[2] == bob_acc.id
        assert parts[3] == "50"

    def test_add_signature(self, alice, alice_acc, bob_acc):
        tx = Transaction(_sender_id=alice_acc.id, _receiver_id=bob_acc.id, _amount=100)
        sig = alice.sign_transaction(tx.canonical_data)
        tx.add_signature(alice_acc.id, sig)
        assert alice_acc.id in tx._signatures

    def test_cannot_sign_non_pending(self, alice, alice_acc, bob_acc):
        tx = Transaction(_sender_id=alice_acc.id, _receiver_id=bob_acc.id, _amount=100)
        tx._status = "COMPLETED"
        with pytest.raises(ValueError):
            tx.add_signature(alice_acc.id, b"fakesig")

    def test_signatures_not_shared_between_instances(self, alice_acc, bob_acc):
        """Проверка что field(default_factory=dict) работает корректно."""
        tx1 = Transaction(_sender_id=alice_acc.id, _receiver_id=bob_acc.id, _amount=10)
        tx2 = Transaction(_sender_id=alice_acc.id, _receiver_id=bob_acc.id, _amount=20)
        tx1._signatures["ACC-TEST"] = b"sig"
        assert "ACC-TEST" not in tx2._signatures


# ─── Bank.create_account ──────────────────────────────────────────────────────

class TestBankCreateAccount:
    def test_returns_account(self, bank, alice):
        acc = bank.create_account(alice.get_public_key())
        assert isinstance(acc, Account)

    def test_account_stored(self, bank, alice):
        acc = bank.create_account(alice.get_public_key())
        assert acc.id in bank._accounts

    def test_rejects_non_rsa_key(self, bank):
        with pytest.raises(TypeError):
            bank.create_account("not-a-key")


# ─── Bank.init_transaction ────────────────────────────────────────────────────

class TestBankInitTransaction:
    def test_returns_transaction(self, bank, alice_acc, bob_acc):
        tx = bank.init_transaction(alice_acc.id, bob_acc.id, 100)
        assert isinstance(tx, Transaction)

    def test_transaction_appended_to_log(self, bank, alice_acc, bob_acc):
        tx = bank.init_transaction(alice_acc.id, bob_acc.id, 100)
        assert tx in bank._transactions

    def test_unknown_sender_raises(self, bank, bob_acc):
        with pytest.raises(ValueError):
            bank.init_transaction("ACC-FAKE", bob_acc.id, 100)

    def test_unknown_receiver_raises(self, bank, alice_acc):
        with pytest.raises(ValueError):
            bank.init_transaction(alice_acc.id, "ACC-FAKE", 100)


# ─── Bank._verify_signature ───────────────────────────────────────────────────

class TestVerifySignature:
    def test_valid_signature_returns_true(self, bank, alice, alice_acc, bob_acc):
        tx = bank.init_transaction(alice_acc.id, bob_acc.id, 100)
        tx.add_signature(alice_acc.id, alice.sign_transaction(tx.canonical_data))
        assert bank._verify_signature(tx, alice_acc.id) is True

    def test_missing_signature_returns_false(self, bank, alice_acc, bob_acc):
        tx = bank.init_transaction(alice_acc.id, bob_acc.id, 100)
        assert bank._verify_signature(tx, alice_acc.id) is False

    def test_wrong_key_returns_false(self, bank, bob, alice_acc, bob_acc):
        """Bob подписывает транзакцию, но проверяется по ключу Alice."""
        tx = bank.init_transaction(alice_acc.id, bob_acc.id, 100)
        # подписываем ключом Bob, но кладём в слот Alice
        tx._signatures[alice_acc.id] = bob.sign_transaction(tx.canonical_data)
        assert bank._verify_signature(tx, alice_acc.id) is False

    def test_tampered_data_returns_false(self, bank, alice, alice_acc, bob_acc):
        """Подпись валидна, но canonical_data изменена после подписания."""
        tx = bank.init_transaction(alice_acc.id, bob_acc.id, 100)
        tx.add_signature(alice_acc.id, alice.sign_transaction(tx.canonical_data))
        tx._amount = 9999  # подменяем сумму после подписания
        assert bank._verify_signature(tx, alice_acc.id) is False

    def test_unknown_account_raises(self, bank, alice_acc, bob_acc):
        tx = bank.init_transaction(alice_acc.id, bob_acc.id, 100)
        with pytest.raises(ValueError):
            bank._verify_signature(tx, "ACC-FAKE")

    def test_account_without_public_key_returns_false(self, bank, alice_acc, bob_acc):
        acc_no_key = Account()  # _public_key=None по умолчанию
        bank._accounts[acc_no_key.id] = acc_no_key
        tx = bank.init_transaction(alice_acc.id, bob_acc.id, 100)
        tx._signatures[acc_no_key.id] = b"anysig"
        assert bank._verify_signature(tx, acc_no_key.id) is False


# ─── Bank.execute_transaction ─────────────────────────────────────────────────

class TestExecuteTransaction:
    def test_happy_path_balances(self, funded_bank, alice, bob):
        bank, alice_acc, bob_acc = funded_bank
        tx = bank.init_transaction(alice_acc.id, bob_acc.id, 300)
        _sign_both(tx, alice, alice_acc, bob, bob_acc)

        result = bank.execute_transaction(tx)

        assert result is True
        assert alice_acc.balance == 700
        assert bob_acc.balance == 500

    def test_status_becomes_completed(self, funded_bank, alice, bob):
        bank, alice_acc, bob_acc = funded_bank
        tx = bank.init_transaction(alice_acc.id, bob_acc.id, 100)
        _sign_both(tx, alice, alice_acc, bob, bob_acc)
        bank.execute_transaction(tx)
        assert tx._status == "COMPLETED"

    def test_missing_sender_signature_raises(self, funded_bank, bob, alice_acc, bob_acc):
        bank, alice_acc, bob_acc = funded_bank
        tx = bank.init_transaction(alice_acc.id, bob_acc.id, 100)
        tx.add_signature(bob_acc.id, bob.sign_transaction(tx.canonical_data))
        with pytest.raises(ValueError):
            bank.execute_transaction(tx)

    def test_missing_receiver_signature_raises(self, funded_bank, alice, alice_acc, bob_acc):
        bank, alice_acc, bob_acc = funded_bank
        tx = bank.init_transaction(alice_acc.id, bob_acc.id, 100)
        tx.add_signature(alice_acc.id, alice.sign_transaction(tx.canonical_data))
        with pytest.raises(ValueError):
            bank.execute_transaction(tx)

    def test_forged_signature_raises(self, funded_bank, alice, bob, alice_acc, bob_acc):
        """Charlie подписывает вместо Bob."""
        bank, alice_acc, bob_acc = funded_bank
        charlie = ClientDevice.generate()
        tx = bank.init_transaction(alice_acc.id, bob_acc.id, 100)
        tx.add_signature(alice_acc.id, alice.sign_transaction(tx.canonical_data))
        tx.add_signature(bob_acc.id, charlie.sign_transaction(tx.canonical_data))
        with pytest.raises(ValueError):
            bank.execute_transaction(tx)

    def test_insufficient_funds_returns_false(self, funded_bank, alice, bob):
        bank, alice_acc, bob_acc = funded_bank
        tx = bank.init_transaction(alice_acc.id, bob_acc.id, 9999)
        _sign_both(tx, alice, alice_acc, bob, bob_acc)
        result = bank.execute_transaction(tx)
        assert result is False

    def test_insufficient_funds_balance_unchanged(self, funded_bank, alice, bob):
        bank, alice_acc, bob_acc = funded_bank
        tx = bank.init_transaction(alice_acc.id, bob_acc.id, 9999)
        _sign_both(tx, alice, alice_acc, bob, bob_acc)
        bank.execute_transaction(tx)
        assert alice_acc.balance == 1000
        assert bob_acc.balance == 200

    def test_cannot_execute_twice(self, funded_bank, alice, bob):
        """Повторный вызов execute на COMPLETED транзакции должен упасть."""
        bank, alice_acc, bob_acc = funded_bank
        tx = bank.init_transaction(alice_acc.id, bob_acc.id, 100)
        _sign_both(tx, alice, alice_acc, bob, bob_acc)
        bank.execute_transaction(tx)
        with pytest.raises(ValueError):
            bank.execute_transaction(tx)

    def test_negative_amount_raises(self, bank, alice, bob, alice_acc, bob_acc):
        tx = bank.init_transaction(alice_acc.id, bob_acc.id, 100)
        tx._amount = -50  # подмена после создания
        _sign_both(tx, alice, alice_acc, bob, bob_acc)
        with pytest.raises(ValueError):
            bank.execute_transaction(tx)

    def test_not_transaction_object_raises(self, bank):
        with pytest.raises(TypeError):
            bank.execute_transaction("not a transaction")


# ─── Bank.verify_ownership ────────────────────────────────────────────────────

class TestVerifyOwnership:
    def test_correct_owner_returns_true(self, bank, alice, alice_acc):
        assert bank.verify_ownership(alice_acc.id, alice.get_public_key_pem()) is True

    def test_wrong_device_returns_false(self, bank, bob, alice_acc):
        assert bank.verify_ownership(alice_acc.id, bob.get_public_key_pem()) is False

    def test_unknown_account_raises(self, bank, alice):
        with pytest.raises(ValueError):
            bank.verify_ownership("ACC-FAKE", alice.get_public_key_pem())

    def test_non_bytes_raises(self, bank, alice_acc):
        with pytest.raises(TypeError):
            bank.verify_ownership(alice_acc.id, "not-bytes")


# ─── Bank._change_balance ─────────────────────────────────────────────────────

class TestChangeBalance:
    def test_positive_delta_increases(self, bank, alice_acc):
        alice_acc._balance = 500
        bank._change_balance(alice_acc, 200)
        assert alice_acc.balance == 700

    def test_negative_delta_decreases(self, bank, alice_acc):
        alice_acc._balance = 500
        bank._change_balance(alice_acc, -200)
        assert alice_acc.balance == 300

    def test_balance_cannot_go_negative(self, bank, alice_acc):
        alice_acc._balance = 100
        result = bank._change_balance(alice_acc, -200)
        assert result is False
        assert alice_acc.balance == 100  # не изменился

    def test_exact_zero_balance_allowed(self, bank, alice_acc):
        alice_acc._balance = 100
        result = bank._change_balance(alice_acc, -100)
        assert result is True
        assert alice_acc.balance == 0

    def test_non_account_raises(self, bank):
        with pytest.raises(TypeError):
            bank._change_balance("not an account", 100)