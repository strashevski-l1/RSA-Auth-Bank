# RSA-Auth-Bank

A secure transaction system combining OOP principles with RSA-2048 digital signatures. 

## Core Concept
Implements cryptographic authentication ensuring transaction integrity and non-repudiation. Both parties must digitally sign transactions using RSA private keys, verified by the bank using public keys.

## Files
- **Bank.py**: Core classes (Bank, Account, Transaction, ClientDevice, BaseEntity) handling account management, transaction execution, and signature verification
- **test.py**: 50+ pytest test cases validating security, functionality, and edge cases
- **mindmap.md**: Project architecture documentation
- **bank_system_flow.svg**: Visual system flow diagram

## Features
Transaction signing, balance management, ownership verification, tampering detection.