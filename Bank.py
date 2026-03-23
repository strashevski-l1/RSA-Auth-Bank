from dataclasses import dataclass, field
from typing import List, Dict, ClassVar
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from abc import ABC
import uuid

from Bank import Bank

@dataclass
class BaseEntity(ABC):
    PREFIX: ClassVar[str] = "GEN"
    _id: str = field(init=False)
    
    def __post_init__(self):
        self._id = f"{self.PREFIX}-{str(uuid.uuid4())[:8]}"

    @property
    def id(self) -> str:
        return self._id 

@dataclass
class Transaction(BaseEntity):
    PREFIX: ClassVar[str] = "TRN"

    _sender_id: str
    _receiver_id: str
    _amount: int
    _status: str = "PENDING"
    _signatures: Dict[str, bytes] = field(default_factory=dict)
    _comment: str = ""

    @property
    def amount(self) -> int:
        return self._amount
    @property
    def canonical_data(self) -> str:
        return f"{self._id}:{self._sender_id}:{self._receiver_id}:{self._amount}"
    
    def add_signature(self, account_id: str, signature: bytes) -> None:
        if self._status != "PENDING":
            raise ValueError("You cant sign non PENDING tx")
        self._signatures[account_id] = signature
    def __repr__(self) -> str:
        signs = list(self._signatures.keys())
        return(
            f"Transaction: {self.id}"
            f"{self._sender_id} to {self._receiver_id}"
            f"amt={self.amount}, status={self._status}, signs={signs}"
        )

@dataclass
class Account(BaseEntity):
    PREFIX: ClassVar[str] = "ACC"

    _balance: int = 0
    _public_key: rsa.RSAPublicKey = None

    @property
    def balance(self) -> int:
        return self._balance
    @property
    def public_key(self) -> rsa.RSAPublicKey:
        return self._public_key
    
    def change_balance(self, bank: Bank, new_balance: int) -> bool:
        if not(isinstance(bank, Bank)):
            raise TypeErrorError("Non Bank can`t update account balance")
        if (new_balance < 0):
            raise ValueError("New balance cant be negative")
        self._balance = new_balance
        return True


@dataclass
class ClientDevice:
    _private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey

    accounts: List[str] = field(default_factory=list) # Добавить логику добавления, и сделать метод проверки владения на стороне Банка

    @classmethod
    def generate(cls, key_size: int = 2048) -> "ClientDevice":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        return cls(
            _private_key=private_key,
            public_key=private_key.public_key(),
        )
    
    def sign_transaction(self, tx_data: str) -> bytes:
        if not (isinstance(tx_data, str)):
            raise TypeError("tx_data must be str.")

        signature = self._private_key.sign(
            tx_data.encode("utf-8"),
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        return signature
    
    def get_public_key(self) -> rsa.RSAPublicKey:
        return self.public_key
    def get_public_key_pem(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )        

class Bank:
    def __init__(self):
        self._accounts: Dict[str, Account] = {}
        self._transactions: List[Transaction] = []
    
    def create_account(self, public_key: rsa.RSAPublicKey) -> Account:
        if not (isinstance(public_key, rsa.RSAPublicKey)):
            raise TypeError("Public_key needs to be an RSAPublickey type")
        new_acc = Account(_public_key = public_key)
        self._accounts[new_acc.id] = new_acc
        return new_acc
    
    def init_transaction(self, sender_id: str, receiver_id: str, amount: int, comment: str = "") -> Transaction:
        if not (sender_id in self._accounts and receiver_id in self._accounts):
            raise ValueError("Sender or receiver does not exist")
        new_transaction = Transaction(
            _sender_id = sender_id, 
            _receiver_id = receiver_id, 
            _amount = amount,
            _comment = comment,
            )
        self._transactions.append(new_transaction)
        return new_transaction
    def _verify_signature(self, transaction: Transaction, account_id: str) -> bool:
        if not(account_id in self._accounts):
            raise ValueError("Account does not exist")
        transaction_signature = transaction._signatures.get(account_id)
        if transaction_signature is None:
            return False
        
        account_public_key = self._accounts[account_id].public_key

        if account_public_key is None:
            return False

        try:
            account_public_key.verify(
                transaction_signature,
                transaction.canonical_data.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        
    def _change_balance(self, account: Account, amount: int) -> bool:
        if not(isinstance(account, Account)):
            raise TypeError("Account is not an Account object")
        new_balance = account.balance + amount

        if new_balance < 0:
            return False
        else:
            account.change_balance(self, new_balance)
            return True

    def execute_transaction(self, transaction: Transaction) -> bool:
        if not(isinstance(transaction, Transaction)):
            raise TypeError("Transaction is not a Transaction Object")
        
        if (transaction._receiver_id not in transaction._signatures or
            transaction._sender_id not in transaction._signatures):
            raise ValueError("Sender or Reciever hasnt signed transaction")
        
        if not (self._verify_signature(transaction, transaction._receiver_id) and 
                self._verify_signature(transaction, transaction._sender_id)):
            raise ValueError("Sender`s or Reciever`s transaction is not valid.")
        
        if transaction._status != "PENDING":
            raise ValueError(f"Transaction already in status {transaction._status}")
        
        if transaction._amount < 0:
            raise ValueError("Transcation ammount can`t be negative")
        
        if self._accounts[transaction._sender_id].balance < transaction._amount:
            return False

        sender_ok = self._change_balance(self._accounts[transaction._sender_id], -transaction._amount)

        if not sender_ok:
            return False
        
        self._change_balance(self._accounts[transaction._receiver_id], transaction._amount)
        transaction._status = "COMPLETED"
        return True

    def verify_ownership(self, account_id: str, device_public_key_pem: bytes) -> bool:
        if not(isinstance(device_public_key_pem, bytes)):
            raise TypeError("Device public key must be an bytes object")
        if (account_id not in self._accounts):
            raise ValueError("Account does not exist")
        
        account = self._accounts[account_id]

        account_public_key_pem = self._accounts[account_id].public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )

        return account_public_key_pem == device_public_key_pem