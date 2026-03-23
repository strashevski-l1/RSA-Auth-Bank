# Bank System Architecture

## 1. ClientDevice
Автономный модуль пользователя. Управляет ключами локально без прямого доступа к БД.

### Поля
| Поле         | Тип           | Описание                        |
|--------------|--------------|----------------------------------|
| _private_key | RSAPrivateKey | Локальный ключ для подписей     |
| public_key   | RSAPublicKey  | Идентификатор в системе         |


### Методы
| Метод            | Сигнатура        | Возвращает           |
|------------------|------------------|----------------------|
| sign_transaction | tx_data: str     | bytes (подпись)      |
| get_public_key   | -                | RSAPublicKey         |
|get_public_key_PEM| -                | bytes                |

---

## 2. Account & Transaction
Data-классы реестра и передачи прав.

### Account
- _id: str (префикс ACC-)
- _balance: int
- _public_key: RSAPublicKey (верификация)

### Transaction
- _id: str (префикс TRN-)
- _sender_id / _receiver_id: str
- _amount: int
- _status: str (PENDING, COMPLETED, REVERSED)
- _signatures: Dict[str, bytes] (подписи сторон)
- _comment: str (метаданные / Chargeback)

---

## 3. Bank (Core Logic)

### Поля
| Поле        | Тип                    | Описание                |
|-------------|------------------------|-------------------------|
| _accounts   | Dict[str, Account]     | Хранилище аккаунтов     |
|_transactions| List[Transaction]      | Неизменяемый лог        |

### Методы
| Метод              | Сигнатура               | Возвращает |
|--------------------|-------------------------|------------|
| create_account     | pub_key: RSAPublicKey   | Account    |
| init_transaction   | s_id, r_id, amt         | Transaction|
| verify_signature   | tx, acc_id              | bool       |
| execute_transaction| tx: Transaction         | bool       |
| _change_balance    | acc, amount             | bool       |
| verify_ownership   | acc_id, device_pem      | bool       |

## Реализация

**Two-Party Sign**  
execute_transaction требует наличия подписей отправителя и получателя в _signatures до списания средств.

**Безопасность**  
Инкапсуляция балансов в Bank. PublicBank оперирует только методами верификации.