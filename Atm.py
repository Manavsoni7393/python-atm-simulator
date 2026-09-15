import sys
import getpass
import hashlib
from datetime import datetime
from typing import Dict, List, Optional
# ==========================================
# 1. CUSTOM EXCEPTION HIERARCHY
# ==========================================
class ATMException(Exception):
    """Base exception class for all ATM system errors."""
    pass
class AuthenticationError(ATMException):
    """Raised when user login or password verification fails."""
    pass
class InvalidPINError(ATMException):
    """Raised when an incorrect PIN is entered."""
    pass
class AccountLockedError(ATMException):
    """Raised when an account is locked due to security violations."""
    pass
class InsufficientFundsError(ATMException):
    """Raised when a transaction amount exceeds available balance."""
    pass
class MinimumBalanceError(ATMException):
    """Raised when an operation violates minimum balance constraints."""
    pass
class InvalidAmountError(ATMException):
    """Raised when a zero, negative, or non-numeric amount is supplied."""
    pass
class AccountNotFoundError(ATMException):
    """Raised when a requested account number does not exist."""
    pass
class ValidationError(ATMException):
    """Raised when user input validation fails (e.g. invalid PIN length)."""
    pass
# ==========================================
# 2. DOMAIN MODELS & ENCAPSULATION
# ==========================================
class Transaction:
    """
    Represents an immutable record of a financial or security transaction.
    """
    def __init__(self, tx_type: str, amount: float, balance_after: float, details: str = ""):
        self.__timestamp = datetime.now()
        self.__tx_type = tx_type
        self.__amount = amount
        self.__balance_after = balance_after
        self.__details = details
    @property
    def timestamp(self) -> datetime:
        return self.__timestamp
    @property
    def tx_type(self) -> str:
        return self.__tx_type
    @property
    def amount(self) -> float:
        return self.__amount
    @property
    def balance_after(self) -> float:
        return self.__balance_after
    @property
    def details(self) -> str:
        return self.__details
    def __str__(self) -> str:
        time_str = self.__timestamp.strftime("%Y-%m-%d %H:%M:%S")
        if self.__amount > 0 or self.__tx_type in ("DEPOSIT", "WITHDRAWAL", "TRANSFER_IN", "TRANSFER_OUT"):
            return f"[{time_str}] {self.__tx_type:<12} | Amount: ${self.__amount:>10,.2f} | Balance: ${self.__balance_after:>10,.2f} | {self.__details}"
        return f"[{time_str}] {self.__tx_type:<12} | {self.__details}"
class Account:
    """
    Represents a bank account using strict encapsulation.
    Sensitive data (passwords, PINs, balances) are private and hashed.
    """
    MINIMUM_BALANCE = 50.0            # Minimum balance required to keep account open
    MINIMUM_INITIAL_DEPOSIT = 100.0   # Minimum deposit required at registration
    def __init__(self, account_number: str, user_full_name: str, initial_deposit: float, password: str, pin: str):
        if initial_deposit < self.MINIMUM_INITIAL_DEPOSIT:
            raise MinimumBalanceError(f"Initial deposit must be at least ${self.MINIMUM_INITIAL_DEPOSIT:,.2f}")
        
        self.__account_number = account_number
        self.__user_full_name = user_full_name.strip()
        self.__balance = float(initial_deposit)
        self.__password_hash = self._hash_credential(password)
        self.__pin_hash = self._hash_credential(pin)
        self.__is_locked = False
        self.__failed_pin_attempts = 0
        self.__transaction_history: List[Transaction] = []
        # Record account creation transaction
        self._record_transaction("ACCOUNT_INIT", initial_deposit, "Initial deposit on account creation")
    @staticmethod
    def _hash_credential(credential: str) -> str:
        """Hashes credentials using SHA-256 to ensure raw passwords/PINs are never stored in memory."""
        return hashlib.sha256(credential.encode('utf-8')).hexdigest()
    # --- Encapsulated Getters ---
    @property
    def account_number(self) -> str:
        return self.__account_number
    @property
    def user_full_name(self) -> str:
        return self.__user_full_name
    @property
    def balance(self) -> float:
        return self.__balance
    @property
    def is_locked(self) -> bool:
        return self.__is_locked
    @property
    def failed_pin_attempts(self) -> int:
        return self.__failed_pin_attempts
    # --- Security Verification Methods ---
    def verify_password(self, password: str) -> bool:
        if self.__is_locked:
            raise AccountLockedError("Account is currently locked. Please contact bank administrator.")
        return self.__password_hash == self._hash_credential(password)
    def verify_pin(self, pin: str) -> bool:
        if self.__is_locked:
            raise AccountLockedError("Account is locked due to security violations.")
        
        if self.__pin_hash == self._hash_credential(pin):
            self.__failed_pin_attempts = 0  # Reset failed counter on successful PIN entry
            return True
        else:
            self.__failed_pin_attempts += 1
            if self.__failed_pin_attempts >= 3:
                self.__is_locked = True
                raise AccountLockedError("Maximum invalid PIN attempts reached (3/3). Account has been LOCKED!")
            raise InvalidPINError(f"Incorrect PIN. Attempts remaining: {3 - self.__failed_pin_attempts}")
    def unlock_account(self) -> None:
        """Administrative unlock."""
        self.__is_locked = False
        self.__failed_pin_attempts = 0
    # --- Financial Operations ---
    def deposit(self, amount: float) -> float:
        if amount <= 0:
            raise InvalidAmountError("Deposit amount must be greater than zero.")
        self.__balance += amount
        self._record_transaction("DEPOSIT", amount, "Cash deposit")
        return self.__balance
    def withdraw(self, amount: float) -> float:
        if amount <= 0:
            raise InvalidAmountError("Withdrawal amount must be greater than zero.")
        if amount > self.__balance:
            raise InsufficientFundsError(f"Insufficient funds. Current available balance: ${self.__balance:,.2f}")
        if (self.__balance - amount) < self.MINIMUM_BALANCE:
            raise MinimumBalanceError(
                f"Withdrawal denied! Account must maintain a minimum balance of ${self.MINIMUM_BALANCE:,.2f}"
            )
        
        self.__balance -= amount
        self._record_transaction("WITHDRAWAL", amount, "Cash withdrawal")
        return self.__balance
    def transfer(self, target_account: 'Account', amount: float) -> None:
        if target_account.account_number == self.__account_number:
            raise InvalidAmountError("Cannot transfer funds to your own account.")
        if amount <= 0:
            raise InvalidAmountError("Transfer amount must be greater than zero.")
        if amount > self.__balance:
            raise InsufficientFundsError(f"Insufficient funds. Current available balance: ${self.__balance:,.2f}")
        if (self.__balance - amount) < self.MINIMUM_BALANCE:
            raise MinimumBalanceError(
                f"Transfer denied! Account must maintain a minimum balance of ${self.MINIMUM_BALANCE:,.2f}"
            )
        
        # Deduct from sender
        self.__balance -= amount
        self._record_transaction("TRANSFER_OUT", amount, f"Transfer to Acc #{target_account.account_number}")
        
        # Credit to recipient
        target_account._receive_transfer(amount, self.__account_number)
    def _receive_transfer(self, amount: float, sender_acc_num: str) -> None:
        """Internal method to record inbound transfer."""
        self.__balance += amount
        self._record_transaction("TRANSFER_IN", amount, f"Transfer from Acc #{sender_acc_num}")
    # --- Credential Updates ---
    def change_pin(self, old_pin: str, new_pin: str) -> None:
        self.verify_pin(old_pin)
        if not (new_pin.isdigit() and len(new_pin) == 4):
            raise ValidationError("New PIN must consist of exactly 4 numeric digits.")
        if self._hash_credential(new_pin) == self.__pin_hash:
            raise ValidationError("New PIN cannot be identical to the current PIN.")
        
        self.__pin_hash = self._hash_credential(new_pin)
        self._record_transaction("PIN_CHANGE", 0.0, "Security PIN updated")
    def change_password(self, old_password: str, new_password: str) -> None:
        if not self.verify_password(old_password):
            raise AuthenticationError("Incorrect current password.")
        if len(new_password) < 6:
            raise ValidationError("New password must be at least 6 characters long.")
        if self._hash_credential(new_password) == self.__password_hash:
            raise ValidationError("New password cannot be identical to the current password.")
        self.__password_hash = self._hash_credential(new_password)
        self._record_transaction("PASS_CHANGE", 0.0, "Account password updated")
    def get_transaction_history(self) -> List[Transaction]:
        """Returns a defensive copy of the transaction history."""
        return self.__transaction_history.copy()
    def _record_transaction(self, tx_type: str, amount: float, details: str) -> None:
        tx = Transaction(tx_type, amount, self.__balance, details)
        self.__transaction_history.append(tx)
# ==========================================
# 3. BANK SYSTEM REPOSITORY
# ==========================================
class Bank:
    """
    Manages accounts, central authentication, and system administration metrics.
    Acts as the in-memory repository following the Repository Pattern.
    """
    def __init__(self, name: str = "Apex Global Bank"):
        self.__name = name
        self.__accounts: Dict[str, Account] = {}
        self.__account_counter = 1000  # Generates account numbers starting at ACC1001
    @property
    def name(self) -> str:
        return self.__name
    def generate_account_number(self) -> str:
        self.__account_counter += 1
        return f"ACC{self.__account_counter}"
    def register_account(self, full_name: str, initial_deposit: float, password: str, pin: str, custom_acc_num: Optional[str] = None) -> Account:
        if custom_acc_num:
            acc_num = custom_acc_num.strip().upper()
            if acc_num in self.__accounts:
                raise ValidationError(f"Account number '{acc_num}' already exists.")
        else:
            acc_num = self.generate_account_number()
        account = Account(acc_num, full_name, initial_deposit, password, pin)
        self.__accounts[acc_num] = account
        return account
    def get_account(self, account_number: str) -> Account:
        acc_num = account_number.strip().upper()
        if acc_num not in self.__accounts:
            raise AccountNotFoundError(f"Account '{acc_num}' was not found in system records.")
        return self.__accounts[acc_num]
    def authenticate(self, account_number: str, password: str) -> Account:
        account = self.get_account(account_number)
        if not account.verify_password(password):
            raise AuthenticationError("Invalid Account Number or Password combination.")
        return account
    # --- System Metrics (Admin Bonus) ---
    def get_total_accounts(self) -> int:
        return len(self.__accounts)
    def get_total_liquidity(self) -> float:
        return sum(acc.balance for acc in self.__accounts.values())
    def get_all_account_numbers(self) -> List[str]:
        return list(self.__accounts.keys())
# ==========================================
# 4. ATM CLI CONTROLLER & INTERFACE
# ==========================================
class ATM:
    """
    Handles terminal UI rendering, user interaction, session state management,
    and post-login PIN security verification.
    """
    def __init__(self, bank: Bank):
        self.__bank = bank
        self.__current_account: Optional[Account] = None
    # --- UI Formatting Helpers ---
    @staticmethod
    def print_header(title: str) -> None:
        print("\n" + "=" * 60)
        print(f"{title.center(60)}")
        print("=" * 60)
    @staticmethod
    def print_divider() -> None:
        print("-" * 60)
    @staticmethod
    def get_masked_input(prompt: str) -> str:
        """
        Masks password input with asterisks (*).
        Falls back to getpass or input if running in an unsupported terminal.
        """
        try:
            import pwinput
            return pwinput.pwinput(prompt=prompt, mask='*')
        except ImportError:
            # Fallback if pwinput is not installed
            try:
                return getpass.getpass(prompt)
            except Exception:
                return input(f"{prompt} (warning: input visible): ")
    @staticmethod
    def get_float_input(prompt: str) -> float:
        raw = input(prompt).strip()
        try:
            val = float(raw)
            return val
        except ValueError:
            raise InvalidAmountError("Invalid input! Please enter a valid numeric dollar amount.")
    @classmethod
    def get_valid_pin_input(cls, prompt: str = "Enter 4-Digit PIN: ") -> str:
        pin = cls.get_masked_input(prompt).strip()
        if not (pin.isdigit() and len(pin) == 4):
            raise ValidationError("PIN must consist of exactly 4 numeric digits.")
        return pin
    # --- Security Check: Post-Login PIN Verification ---
    def challenge_pin(self) -> bool:
        """
        Prompts user for their 4-digit PIN prior to sensitive operations.
        Locks the account and terminates session after 3 consecutive invalid attempts.
        """
        if not self.__current_account:
            return False
        attempts = 0
        max_attempts = 3
        while attempts < max_attempts:
            try:
                pin = self.get_valid_pin_input(f"SECURITY CHECK - Enter PIN (Attempt {attempts + 1}/{max_attempts}): ")
                if self.__current_account.verify_pin(pin):
                    print("✅ PIN Verification Successful!")
                    return True
            except (InvalidPINError, ValidationError) as e:
                print(f"❌ {e}")
                attempts += 1
            except AccountLockedError as e:
                print(f"\n🔒 SECURITY LOCKOUT: {e}")
                self.__current_account = None
                return False
        print("\n🔒 Session terminated due to multiple incorrect PIN entries.")
        self.__current_account = None
        return False
    # --- Pre-populated Demo Data ---
    def seed_demo_data(self) -> None:
        """"Seeds the bank with 3 pre-configured demo user accounts."""
        try:
            self.__bank.register_account(
                full_name="John Doe",
                initial_deposit=1500.00,
                password="password123",
                pin="1234",
                custom_acc_num="ACC1001"
            )
            self.__bank.register_account(
                full_name="Jane Smith",
                initial_deposit=2850.50,
                password="securePass1!",
                pin="4321",
                custom_acc_num="ACC1002"
            )
            self.__bank.register_account(
                full_name="Alice Johnson",
                initial_deposit=500.00,
                password="alicepass2026",
                pin="9999",
                custom_acc_num="ACC1003"
            )
        except ATMException:
            pass  # Already seeded
    # --- Workflows: Public Menu ---
    def register_user_workflow(self) -> None:
        self.print_header("NEW USER ACCOUNT REGISTRATION")
        try:
            name = input("Enter Full Name: ").strip()
            if not name or any(char.isdigit() for char in name):
                raise ValidationError("Full name cannot be empty or contain numeric digits.")
            deposit = self.get_float_input(f"Enter Initial Deposit (Minimum ${Account.MINIMUM_INITIAL_DEPOSIT:,.2f}): $")
            password = self.get_masked_input("Create Password (min 6 characters): ")
            if len(password) < 6:
                raise ValidationError("Password must be at least 6 characters long.")
            confirm_password = self.get_masked_input("Confirm Password: ")
            if password != confirm_password:
                raise ValidationError("Passwords do not match!")
            pin = self.get_valid_pin_input("Create 4-Digit Security PIN: ")
            confirm_pin = self.get_valid_pin_input("Confirm 4-Digit Security PIN: ")
            if pin != confirm_pin:
                raise ValidationError("PINs do not match!")
            account = self.__bank.register_account(name, deposit, password, pin)
            
            print("\n🎉 Account Successfully Created!")
            print(f"   Account Holder : {account.user_full_name}")
            print(f"   Account Number : {account.account_number}")
            print(f"   Initial Balance: ${account.balance:,.2f}")
            print("\n⚠️  Please save your Account Number, Password, and PIN for future logins!")
        except ATMException as e:
            print(f"\n❌ Registration Failed: {e}")
        except Exception as e:
            print(f"\n❌ Unexpected Error: {e}")
    def login_workflow(self) -> None:
        self.print_header("CUSTOMER LOGIN")
        try:
            acc_num = input("Enter Account Number: ").strip().upper()
            password = self.get_masked_input("Enter Password: ")
            account = self.__bank.authenticate(acc_num, password)
            self.__current_account = account
            print(f"\n✅ Login Successful! Welcome back, {account.user_full_name}.")
            self.customer_menu_loop()
        except ATMException as e:
            print(f"\n❌ Login Failed: {e}")
    def admin_info_workflow(self) -> None:
        self.print_header("SYSTEM ADMIN & METRICS OVERVIEW")
        print(f" Institution Name   : {self.__bank.name}")
        print(f" Total Accounts     : {self.__bank.get_total_accounts()} registered account(s)")
        print(f" Total Bank Reserve : ${self.__bank.get_total_liquidity():,.2f}")
        print(f" Core System Status : ONLINE / OPERATIONAL")
        self.print_divider()
        print(" Active User Accounts Directory:")
        for acc_num in self.__bank.get_all_account_numbers():
            acc = self.__bank.get_account(acc_num)
            status = "LOCKED" if acc.is_locked else "ACTIVE"
            print(f"  • {acc.account_number} | {acc.user_full_name:<20} | Status: {status:<6} | Balance: ${acc.balance:>10,.2f}")
    # --- Workflows: Customer Menu ---
    def show_balance_workflow(self) -> None:
        self.print_header("ACCOUNT BALANCE SUMMARY")
        print(f" Account Holder   : {self.__current_account.user_full_name}")
        print(f" Account Number   : {self.__current_account.account_number}")
        print(f" Available Balance: ${self.__current_account.balance:,.2f}")
        print(f" Minimum Required : ${Account.MINIMUM_BALANCE:,.2f}")
    def deposit_workflow(self) -> None:
        self.print_header("DEPOSIT MONEY")
        try:
            amount = self.get_float_input("Enter amount to deposit: $")
            new_balance = self.__current_account.deposit(amount)
            print(f"\n✅ Deposit Successful!")
            print(f"   Deposited Amount : ${amount:,.2f}")
            print(f"   Updated Balance  : ${new_balance:,.2f}")
        except ATMException as e:
            print(f"\n❌ Deposit Failed: {e}")
    def withdraw_workflow(self) -> None:
        self.print_header("WITHDRAW CASH")
        if not self.challenge_pin():
            return
        try:
            amount = self.get_float_input("Enter amount to withdraw: $")
            new_balance = self.__current_account.withdraw(amount)
            print(f"\n✅ Cash Dispensed! Please collect your funds.")
            print(f"   Withdrawn Amount : ${amount:,.2f}")
            print(f"   Remaining Balance: ${new_balance:,.2f}")
        except ATMException as e:
            print(f"\n❌ Withdrawal Failed: {e}")
    def transfer_workflow(self) -> None:
        self.print_header("TRANSFER FUNDS")
        try:
            target_acc_num = input("Enter Recipient Account Number: ").strip().upper()
            target_account = self.__bank.get_account(target_acc_num)
            
            print(f" Recipient Verified: {target_account.user_full_name} ({target_account.account_number})")
            amount = self.get_float_input("Enter amount to transfer: $")
            if not self.challenge_pin():
                return
            self.__current_account.transfer(target_account, amount)
            print(f"\n✅ Transfer Successful!")
            print(f"   Transferred ${amount:,.2f} to {target_account.user_full_name} ({target_account.account_number})")
            print(f"   New Available Balance: ${self.__current_account.balance:,.2f}")
        except ATMException as e:
            print(f"\n❌ Transfer Failed: {e}")
    def change_pin_workflow(self) -> None:
        self.print_header("CHANGE SECURITY PIN")
        try:
            old_pin = self.get_masked_input("Enter Current 4-Digit PIN: ")
            new_pin = self.get_valid_pin_input("Enter New 4-Digit PIN: ")
            confirm_new_pin = self.get_valid_pin_input("Confirm New 4-Digit PIN: ")
            if new_pin != confirm_new_pin:
                raise ValidationError("New PIN entries do not match!")
            self.__current_account.change_pin(old_pin, new_pin)
            print("\n✅ Security PIN successfully updated!")
        except ATMException as e:
            print(f"\n❌ PIN Change Failed: {e}")
    def change_password_workflow(self) -> None:
        self.print_header("CHANGE ACCOUNT PASSWORD")
        try:
            old_pass = self.get_masked_input("Enter Current Password: ")
            new_pass = self.get_masked_input("Enter New Password (min 6 chars): ")
            confirm_pass = self.get_masked_input("Confirm New Password: ")
            if new_pass != confirm_pass:
                raise ValidationError("New password entries do not match!")
            self.__current_account.change_password(old_pass, new_pass)
            print("\n✅ Account Password successfully updated!")
        except ATMException as e:
            print(f"\n❌ Password Change Failed: {e}")
    def mini_statement_workflow(self) -> None:
        self.print_header("MINI-STATEMENT / TRANSACTION HISTORY")
        history = self.__current_account.get_transaction_history()
        
        if not history:
            print(" No transaction history recorded.")
            return
        print(f" Transaction Audit Log for Account #{self.__current_account.account_number}:")
        self.print_divider()
        for tx in history[-10:]:  # Display last 10 transactions
            print(f" {tx}")
        self.print_divider()
        print(f" Current Available Balance: ${self.__current_account.balance:,.2f}")
    # --- Menu Loops ---
    def customer_menu_loop(self) -> None:
        while self.__current_account is not None:
            self.print_header(f"CUSTOMER PORTAL - {self.__current_account.user_full_name.upper()}")
            print(" 1. View Account Balance")
            print(" 2. Deposit Money")
            print(" 3. Withdraw Cash (PIN Security Check)")
            print(" 4. Transfer Funds (PIN Security Check)")
            print(" 5. View Mini-Statement / Audit Log")
            print(" 6. Change 4-Digit Security PIN")
            print(" 7. Change Password")
            print(" 8. Logout")
            self.print_divider()
            choice = input("Select an option (1-8): ").strip()
            if choice == "1":
                self.show_balance_workflow()
            elif choice == "2":
                self.deposit_workflow()
            elif choice == "3":
                self.withdraw_workflow()
            elif choice == "4":
                self.transfer_workflow()
            elif choice == "5":
                self.mini_statement_workflow()
            elif choice == "6":
                self.change_pin_workflow()
            elif choice == "7":
                self.change_password_workflow()
            elif choice == "8":
                print(f"\n👋 Logging out... Thank you for choosing {self.__bank.name}!")
                self.__current_account = None
            else:
                print("\n❌ Invalid option! Please select a choice between 1 and 8.")
    def public_menu_loop(self) -> None:
        self.seed_demo_data()
        while True:
            self.print_header(f"WELCOME TO {self.__bank.name.upper()} ATM")
            print(" 1. Login to Account")
            print(" 2. Register New Account")
            print(" 3. Admin / System Status & Demo Accounts")
            print(" 4. Exit Application")
            self.print_divider()
            choice = input("Select an option (1-4): ").strip()
            if choice == "1":
                self.login_workflow()
            elif choice == "2":
                self.register_user_workflow()
            elif choice == "3":
                self.admin_info_workflow()
            elif choice == "4":
                print(f"\nThank you for using {self.__bank.name}. Have a safe day! Goodbye!\n")
                sys.exit(0)
            else:
                print("\n❌ Invalid option! Please select a choice between 1 and 4.")
# ==========================================
# 5. ENTRY POINT
# ==========================================
def main():
    bank = Bank("Apex Global Bank")
    atm = ATM(bank)
    try:
        atm.public_menu_loop()
    except KeyboardInterrupt:
        print("\n\n⚠️ System session interrupted by user. Exiting safely...")
        sys.exit(0)
if __name__ == "__main__":
    main()