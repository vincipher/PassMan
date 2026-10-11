import base64
import getpass
import json
import os
import secrets
import string
import subprocess
import tempfile
from pathlib import Path

import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

# ============================================================
# VAULT - SECURE PASSWORD MANAGER
# ============================================================

console = Console()
APP_DIR = Path.home() / ".local" / "share" / "secure_password_manager"
CONFIG_FILE = APP_DIR / "master.json"
VAULT_FILE = APP_DIR / "vault.enc"
SALT_SIZE = 16
KEY_LENGTH = 32
MAX_PASSWORD_LENGTH = 4096
VERIFIER = b"vault-master-password-verification-v1"


class VaultError(Exception):
    """Raised when vault data cannot safely be accessed."""


# ============================================================
# STORAGE
# ============================================================

def initialize_storage():
    APP_DIR.mkdir(parents=True, exist_ok=True)
    APP_DIR.chmod(0o700)


def atomic_write(path, content):
    """Write a file via a temporary file to reduce partial-write risk."""
    fd = None
    temp_path = None
    try:
        fd, temp_name = tempfile.mkstemp(prefix=".tmp_", dir=path.parent)
        temp_path = Path(temp_name)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as file:
            fd = None
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp_path, path)
        temp_path = None
    except OSError as exc:
        raise VaultError(f"Could not write {path.name}.") from exc
    finally:
        if fd is not None:
            os.close(fd)
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


def read_json(path):
    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VaultError(f"{path.name} is missing, unreadable, or corrupted.") from exc


def write_json(path, data):
    try:
        content = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise VaultError("Could not encode application data.") from exc
    atomic_write(path, content)


# ============================================================
# ENCRYPTION AND MASTER PASSWORD
# ============================================================

def derive_key(password, salt):
    if not password:
        raise ValueError("Master password cannot be empty.")
    kdf = Scrypt(salt=salt, length=KEY_LENGTH, n=2**14, r=8, p=1)
    raw_key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw_key)


def encrypt_text(text, key):
    return Fernet(key).encrypt(text.encode("utf-8")).decode("ascii")


def decrypt_text(token, key):
    try:
        return Fernet(key).decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeError, TypeError) as exc:
        raise VaultError("Decryption failed.") from exc


def create_master_password():
    if CONFIG_FILE.exists() or VAULT_FILE.exists():
        raise VaultError(
            "Existing vault files were detected. Refusing to initialize over existing data."
        )

    console.print(Panel(
        "[bold cyan]WELCOME TO VAULT[/bold cyan]\n\n"
        "Create a strong master password to secure your vault.",
        border_style="cyan", box=box.DOUBLE,
    ))

    while True:
        password = getpass.getpass("Create master password: ")
        if len(password) < 12:
            console.print("[yellow]Use at least 12 characters.[/yellow]")
            continue
        confirmation = getpass.getpass("Confirm master password: ")
        if password != confirmation:
            console.print("[red]Passwords do not match.[/red]")
            continue
        break

    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    config = {
        "version": 1,
        "salt": base64.b64encode(salt).decode("ascii"),
        "verifier": encrypt_text(VERIFIER.decode("ascii"), key),
        "mfa_enabled": False,
        "mfa_secret": None,
    }
    write_json(CONFIG_FILE, config)
    console.print("[bold green]Master password created successfully![/bold green]")
    return key, config


def authenticate():
    if not CONFIG_FILE.exists():
        return create_master_password()

    config = read_json(CONFIG_FILE)
    try:
        if config.get("version") != 1:
            raise VaultError("Unsupported configuration version.")
        salt = base64.b64decode(config["salt"], validate=True)
        if len(salt) != SALT_SIZE:
            raise VaultError("Invalid encryption salt.")
        if not isinstance(config.get("mfa_enabled"), bool):
            raise VaultError("Invalid MFA configuration.")
        if config["mfa_enabled"] and not config.get("mfa_secret"):
            raise VaultError("MFA configuration is incomplete.")
    except (KeyError, TypeError, ValueError) as exc:
        raise VaultError("Master configuration is malformed.") from exc

    for attempt in range(3):
        password = getpass.getpass("Master password: ")
        try:
            key = derive_key(password, salt)
            verifier = decrypt_text(config["verifier"], key)
            if not secrets.compare_digest(verifier, VERIFIER.decode("ascii")):
                raise VaultError("Incorrect master password.")
            break
        except (VaultError, ValueError):
            console.print("[red]Incorrect master password.[/red]")
            if attempt == 2:
                return None, None

    if config["mfa_enabled"]:
        secret = decrypt_text(config["mfa_secret"], key)
        console.print("[cyan]Enter your authenticator code.[/cyan]")
        if not verify_mfa(secret):
            console.print("[bold red]MFA verification failed.[/bold red]")
            return None, None

    console.print("[bold green]Vault unlocked successfully![/bold green]")
    return key, config


# ============================================================
# PASSWORD VAULT
# ============================================================

def load_vault(key):
    if not VAULT_FILE.exists():
        return {}
    try:
        encrypted = VAULT_FILE.read_bytes()
        plaintext = Fernet(key).decrypt(encrypted)
        data = json.loads(plaintext.decode("utf-8"))
        if not isinstance(data, dict):
            raise VaultError("Invalid vault format.")
        for service, entry in data.items():
            if (not isinstance(service, str) or not isinstance(entry, dict)
                    or not isinstance(entry.get("username"), str)
                    or not isinstance(entry.get("password"), str)):
                raise VaultError("Vault contains an invalid entry.")
        return data
    except (OSError, UnicodeError, json.JSONDecodeError, InvalidToken, ValueError, TypeError) as exc:
        raise VaultError(
            "Vault is corrupted or cannot be decrypted. Existing data has not been reset."
        ) from exc


def save_vault(data, key):
    try:
        plaintext = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        encrypted = Fernet(key).encrypt(plaintext)
        atomic_write(VAULT_FILE, encrypted)
    except (OSError, ValueError, TypeError) as exc:
        if isinstance(exc, VaultError):
            raise
        raise VaultError("Could not encrypt or save the vault.") from exc


def save_password(key):
    console.print(Panel("[bold cyan]SAVE ACCOUNT[/bold cyan]", border_style="cyan"))
    service = console.input("[cyan]Service name: [/cyan]").strip()
    username = console.input("[cyan]Username/email: [/cyan]").strip()
    password = getpass.getpass("Password: ")

    if not service:
        console.print("[red]Service name cannot be empty.[/red]")
        return
    if not username:
        console.print("[red]Username cannot be empty.[/red]")
        return

    try:
        data = load_vault(key)
        existing = next((name for name in data if name.casefold() == service.casefold()), None)
        if existing is not None:
            answer = console.input(
                f"[yellow]{existing} already exists. Overwrite? (y/N): [/yellow]"
            ).strip().lower()
            if answer != "y":
                console.print("[dim]Save cancelled.[/dim]")
                return
            service = existing
        data[service] = {"username": username, "password": password}
        save_vault(data, key)
        console.print(Panel(
            f"[bold green]Account saved successfully![/bold green]\nService: {service}",
            border_style="green",
        ))
    except VaultError as exc:
        console.print(f"[bold red]Vault error:[/bold red] {exc}")


def browse_accounts(key):
    """List saved accounts without revealing passwords."""
    try:
        data = load_vault(key)
    except VaultError as exc:
        console.print(f"[red]Vault error: {exc}[/red]")
        return

    if not data:
        console.print(Panel(
            "No accounts saved yet.\nChoose Save Account to get started.",
            title="Your Vault Is Empty", border_style="yellow",
        ))
        return

    accounts = sorted(data.items(), key=lambda item: item[0].casefold())
    query = console.input(
        "\n[cyan]Search service or username (Enter to show all): [/cyan]"
    ).strip().casefold()
    if query:
        accounts = [
            (service, entry) for service, entry in accounts
            if query in service.casefold() or query in entry["username"].casefold()
        ]

    if not accounts:
        console.print("[yellow]No matching accounts found.[/yellow]")
        return

    table = Table(
        title="YOUR SAVED ACCOUNTS", box=box.ROUNDED,
        border_style="bright_cyan", header_style="bold bright_cyan", show_lines=True,
    )
    table.add_column("#", justify="right", style="dim", width=4)
    table.add_column("Service", style="bold white")
    table.add_column("Username", style="green")
    table.add_column("Password", style="dim")
    for number, (service, entry) in enumerate(accounts, 1):
        table.add_row(str(number), service, entry["username"], "••••••••")
    console.print(table)
    console.print("[dim]Passwords remain hidden while browsing.[/dim]")

    selection = console.input(
        "\n[cyan]Enter account number to retrieve (Enter to cancel): [/cyan]"
    ).strip()
    if not selection:
        console.print("[dim]Cancelled.[/dim]")
        return
    if not selection.isdigit():
        console.print("[red]Enter a valid account number.[/red]")
        return
    number = int(selection)
    if not 1 <= number <= len(accounts):
        console.print("[red]Account number out of range.[/red]")
        return

    service, entry = accounts[number - 1]
    console.print(Panel(
        f"[bold]Service:[/bold] {service}\n[bold]Username:[/bold] {entry['username']}",
        title="ACCOUNT DETAILS", border_style="cyan",
    ))
    reveal = console.input("[yellow]Reveal password? (y/N): [/yellow]").strip().lower()
    if reveal == "y":
        console.print(Panel(entry["password"], title="Password", border_style="green"))
    else:
        console.print("[dim]Password kept hidden.[/dim]")


# ============================================================
# PASSWORD GENERATOR
# ============================================================

def generate_password(length=16):
    if isinstance(length, bool) or not isinstance(length, int):
        raise ValueError("Length must be an integer.")
    if not 8 <= length <= MAX_PASSWORD_LENGTH:
        raise ValueError("Length must be between 8 and 4096.")
    groups = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        "!@#$%^&*()-_=+[]{}:,.?",
    ]
    chars = [secrets.choice(group) for group in groups]
    all_chars = "".join(groups)
    chars.extend(secrets.choice(all_chars) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def password_generator():
    console.print(Panel("[bold cyan]PASSWORD GENERATOR[/bold cyan]", border_style="cyan"))
    raw_length = console.input("[cyan]Length [16]: [/cyan]").strip()
    try:
        length = int(raw_length) if raw_length else 16
        password = generate_password(length)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        return
    console.print(Panel(f"[bold green]{password}[/bold green]", title="GENERATED PASSWORD", border_style="green"))
    console.print("[dim]Copy it manually if you need to save it elsewhere.[/dim]")


# ============================================================
# MULTI-FACTOR AUTHENTICATION
# ============================================================

def verify_mfa(secret):
    totp = pyotp.TOTP(secret)
    for attempt in range(3):
        code = console.input("[cyan]6-digit MFA code: [/cyan]").strip()
        if len(code) == 6 and code.isdigit() and totp.verify(code, valid_window=1):
            return True
        if attempt < 2:
            console.print("[red]Invalid or expired code.[/red]")
    return False


def setup_mfa(key, config):
    if config["mfa_enabled"]:
        console.print("[yellow]MFA is already enabled. This menu does not reset or disable MFA.[/yellow]")
        return

    secret = pyotp.random_base32()
    uri = pyotp.TOTP(secret).provisioning_uri(
        name="User", issuer_name="VAULT Password Manager"
    )
    qr_path = APP_DIR / "mfa_qr.png"

    console.print(Panel(
        "Scan the QR code with your authenticator app.\n"
        "Confirm enrollment with a valid code.\n\n"
        "The QR image contains your MFA secret; do not share it.",
        title="SET UP MFA", border_style="cyan",
    ))

    try:
        qrcode.make(uri).save(qr_path)
        qr_path.chmod(0o600)
        # Open with the desktop's registered default image viewer.
        subprocess.Popen(["loupe", str(qr_path)])
    except (OSError, Exception) as exc:
        console.print(f"[red]Could not create/open QR image: {exc}[/red]")
        console.print(f"[yellow]QR image path, if created: {qr_path}[/yellow]")
        console.print("[dim]MFA was not enabled. You may open the image manually.[/dim]")
        return

    console.print("[dim]If the image does not open, open this file manually:[/dim]")
    console.print(str(qr_path))

    if not verify_mfa(secret):
        console.print("[yellow]MFA setup cancelled. MFA remains disabled.[/yellow]")
        return

    updated = dict(config)
    updated["mfa_enabled"] = True
    updated["mfa_secret"] = encrypt_text(secret, key)
    try:
        write_json(CONFIG_FILE, updated)
        config.update(updated)
        console.print("[bold green]MFA enabled successfully![/bold green]")
        try:
            qr_path.unlink(missing_ok=True)
            console.print("[dim]Temporary QR image deleted.[/dim]")
        except OSError:
            console.print(f"[yellow]Please delete the QR image manually: {qr_path}[/yellow]")
    except VaultError as exc:
        console.print(f"[red]Could not save MFA settings: {exc}[/red]")
        console.print(f"[yellow]Please delete the QR image manually: {qr_path}[/yellow]")


# ============================================================
# TERMINAL UI
# ============================================================

def show_banner():
    console.print(Panel(
        "[bold bright_cyan]V A U L T[/bold bright_cyan]\n"
        "[dim]Your credentials. One secure place.[/dim]",
        box=box.DOUBLE, border_style="bright_cyan", padding=(1, 4),
    ))


def show_menu():
    table = Table(
        box=box.ROUNDED, border_style="bright_blue",
        show_header=False, padding=(0, 2),
    )
    table.add_column("Key", style="bold bright_cyan", width=6)
    table.add_column("Action", style="bold white")
    table.add_column("Description", style="dim")
    table.add_row("1", "Save Account", "Store a new credential")
    table.add_row("2", "Browse Accounts", "Search services and retrieve passwords")
    table.add_row("3", "Password Generator", "Generate a strong password")
    table.add_row("4", "Setup MFA", "Enable authenticator verification")
    table.add_row("5", "Exit", "Close the password manager")
    console.print(table)


def main():
    try:
        initialize_storage()
    except (OSError, VaultError) as exc:
        console.print(f"[bold red]Startup failed:[/bold red] {exc}")
        return

    try:
        key, config = authenticate()
    except (VaultError, OSError, ValueError) as exc:
        console.print(f"[bold red]Authentication error:[/bold red] {exc}")
        return
    except (KeyboardInterrupt, EOFError):
        console.print("\n[yellow]Cancelled.[/yellow]")
        return

    if key is None:
        console.print("[bold red]Unable to unlock vault.[/bold red]")
        return

    while True:
        try:
            console.clear()
            show_banner()
            try:
                count = len(load_vault(key))
                console.print(f"[dim]Saved accounts: {count}[/dim]\n")
            except VaultError as exc:
                console.print(f"[bold red]Vault error:[/bold red] {exc}\n")
            show_menu()
            choice = console.input("\n[bold bright_cyan]VAULT[/bold bright_cyan] [dim]›[/dim] ").strip()

            if choice == "1":
                save_password(key)
            elif choice == "2":
                browse_accounts(key)
            elif choice == "3":
                password_generator()
            elif choice == "4":
                setup_mfa(key, config)
            elif choice == "5":
                console.print(Panel("[bold cyan]Vault closed. Stay secure![/bold cyan]", border_style="cyan"))
                break
            else:
                console.print("[red]Invalid option. Choose 1–5.[/red]")

            if choice != "5":
                console.input("\n[dim]Press Enter to return to the menu...[/dim]")

        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Vault closed.[/yellow]")
            break
        except (VaultError, OSError) as exc:
            console.print(f"[bold red]Operation failed:[/bold red] {exc}")
            try:
                console.input("\n[dim]Press Enter to continue...[/dim]")
            except (KeyboardInterrupt, EOFError):
                break


if __name__ == "__main__":
    main()
