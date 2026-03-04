import json
import os
import select
import sys
import threading
import time
from typing import List, Dict, Any

import paramiko
from rich.console import Console
from rich.table import Table
from rich.prompt import IntPrompt, Confirm
from rich.text import Text

try:
    import msvcrt  # type: ignore[attr-defined]
except ImportError:
    msvcrt = None  # type: ignore[assignment]

try:
    import termios
    import tty
except ImportError:
    termios = None  # type: ignore[assignment]
    tty = None  # type: ignore[assignment]


console = Console()

# При запуске из exe (PyInstaller) — данные рядом с исполняемым файлом
if getattr(sys, "frozen", False):
    _BASE_DIR = os.path.dirname(sys.executable)
else:
    _BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PROFILES_FILE = os.path.join(_BASE_DIR, "profiles.json")


SESSIONS: List["SshSession"] = []


class SshSession:
    def __init__(self, client: paramiko.SSHClient, channel: Any, title: str) -> None:
        self.client = client
        self.channel = channel
        self.title = title
        self.buffer: List[str] = []
        self.lock = threading.Lock()
        self.alive = True
        self._reader = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader.start()

    def _reader_loop(self) -> None:
        try:
            while True:
                try:
                    if self.channel.recv_ready():
                        data = self.channel.recv(4096)
                    else:
                        time.sleep(0.01)
                        continue
                except Exception:
                    break
                if not data:
                    break
                text = data.decode(errors="ignore")
                with self.lock:
                    self.buffer.append(text)
        finally:
            self.alive = False

    def flush_output(self) -> None:
        with self.lock:
            if not self.buffer:
                return
            data = "".join(self.buffer)
            self.buffer.clear()
        sys.stdout.write(data)
        sys.stdout.flush()

    def close(self) -> None:
        try:
            self.channel.close()
        except Exception:
            pass
        try:
            self.client.close()
        except Exception:
            pass
        self.alive = False


def load_profiles() -> List[Dict[str, Any]]:
    if not os.path.exists(PROFILES_FILE):
        return []
    with open(PROFILES_FILE, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return []
        except json.JSONDecodeError:
            console.print("[red]Ошибка чтения profiles.json[/red]")
            return []


def save_profiles(profiles: List[Dict[str, Any]]) -> None:
    with open(PROFILES_FILE, "w", encoding="utf-8") as f:
        json.dump(profiles, f, ensure_ascii=False, indent=2)


def show_profiles(profiles: List[Dict[str, Any]]) -> None:
    table = Table(title="SSH Профили", show_lines=True)
    table.add_column("#", justify="right", style="cyan", no_wrap=True)
    table.add_column("Имя", style="bold")
    table.add_column("Host")
    table.add_column("Port")
    table.add_column("User")
    table.add_column("Auth")
    table.add_column("Описание")

    if not profiles:
        console.print("[yellow]Профили не найдены. Добавьте новый профиль.[/yellow]")
        return

    for idx, p in enumerate(profiles, start=1):
        table.add_row(
            str(idx),
            p.get("name", ""),
            p.get("host", ""),
            str(p.get("port", 22)),
            p.get("username", ""),
            p.get("auth_type", "password"),
            p.get("description", ""),
        )
    console.print(table)


def add_profile(profiles: List[Dict[str, Any]]) -> None:
    console.print(Text("Добавление нового профиля", style="bold green"))
    name = input("Имя профиля: ").strip()
    host = input("Host (IP/домен): ").strip()
    port_str = input("Порт [22]: ").strip() or "22"
    username = input("Имя пользователя: ").strip()
    auth_type = input("Тип аутентификации [password/ssh_key] (по умолчанию password): ").strip() or "password"

    try:
        port = int(port_str)
    except ValueError:
        console.print("[red]Некорректный порт, используется 22[/red]")
        port = 22

    profile: Dict[str, Any] = {
        "name": name or f"{username}@{host}",
        "host": host,
        "port": port,
        "username": username,
        "auth_type": auth_type,
        "description": input("Описание (необязательно): ").strip(),
    }

    if auth_type == "password":
        profile["password"] = input("Пароль (будет сохранён в profiles.json): ")
    else:
        profile["key_path"] = input("Путь к приватному ключу (например, ~/.ssh/id_rsa): ").strip()
        passphrase = input("Passphrase для ключа (оставьте пустым, если ключ не защищён): ").strip()
        if passphrase:
            profile["key_passphrase"] = passphrase

    profiles.append(profile)
    save_profiles(profiles)
    console.print("[green]Профиль сохранён.[/green]")


def _load_private_key(key_path: str, passphrase: str | None = None) -> paramiko.PKey | None:
    """Загружает приватный ключ (RSA, Ed25519, ECDSA), при необходимости с passphrase."""
    key_path = os.path.expanduser(key_path)
    if not os.path.exists(key_path):
        return None
    for key_class in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey):
        try:
            return key_class.from_private_key_file(key_path, password=passphrase or None)
        except paramiko.ssh_exception.SSHException as e:
            err = str(e).lower()
            if "encrypted" in err or "passphrase" in err:
                raise
            continue
        except Exception:
            continue
    return None


def _create_ssh_session(profile: Dict[str, Any]) -> "SshSession | None":
    host = profile["host"]
    port = profile.get("port", 22)
    username = profile["username"]
    auth_type = profile.get("auth_type", "password")

    password: str | None = None
    pkey: paramiko.PKey | None = None

    if auth_type == "password":
        password = profile.get("password")
        if not password:
            password = input("Пароль: ")
    else:
        key_path = os.path.expanduser(profile.get("key_path", ""))
        if not key_path:
            key_path = os.path.expanduser(input("Путь к приватному ключу: ").strip())
        if not os.path.exists(key_path):
            console.print(f"[red]Ключ не найден: {key_path}[/red]")
            return None
        key_passphrase = profile.get("key_passphrase") or None
        try:
            pkey = _load_private_key(key_path, key_passphrase)
        except paramiko.ssh_exception.SSHException as e:
            if "encrypted" in str(e).lower() or "passphrase" in str(e).lower():
                key_passphrase = input("Введите passphrase для ключа: ")
                pkey = _load_private_key(key_path, key_passphrase or None)
            else:
                console.print(f"[red]Ошибка чтения ключа: {e}[/red]")
                return None
        if pkey is None:
            console.print("[red]Не удалось прочитать ключ (поддерживаются RSA, Ed25519, ECDSA).[/red]")
            return None

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    console.print(f"[cyan]Подключение к {username}@{host}:{port} ...[/cyan]")

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            pkey=pkey,
            look_for_keys=False,
            allow_agent=False,
        )
    except Exception as e:
        console.print(f"[red]Не удалось подключиться: {e}[/red]")
        return None

    channel = client.invoke_shell()
    channel.settimeout(0.0)

    title = profile.get("name", f"{username}@{host}")
    console.print("[green]Подключено. Открывается интерактивная сессия SSH.[/green]")

    return SshSession(client, channel, title)


def _read_key_windows() -> str:
    assert msvcrt is not None
    ch = msvcrt.getch()
    if not ch:
        return ""
    code = ch[0]
    return _decode_control_key(code, ch.decode(errors="ignore"))


def _decode_control_key(code: int, fallback: str = "") -> str:
    if code == 3:  # Ctrl+C
        raise KeyboardInterrupt
    if code == 14:  # Ctrl+N
        return "CTRL_N"
    if code == 16:  # Ctrl+P
        return "CTRL_P"
    if code == 17:  # Ctrl+Q
        return "CTRL_Q"
    if code == 24:  # Ctrl+X
        return "CTRL_X"
    if code == 13:
        return "\r"
    if code == 8:
        return "\b"
    if code == 9:
        return "\t"
    return fallback


def _multisession_available() -> bool:
    """Многосессионный режим доступен: bash (termios) или консоль Windows (msvcrt)."""
    if not sys.stdin.isatty():
        return False
    if termios is not None:
        return True
    if os.name == "nt" and msvcrt is not None:
        return True
    return False


def _session_manager() -> None:
    if not SESSIONS:
        console.print("[yellow]Нет активных SSH-сессий.[/yellow]")
        return

    active_index = 0
    console.print(
        "\n[bold cyan]Управление SSH-сессиями[/bold cyan]\n"
        "[dim]Ctrl+N — следующая сессия, Ctrl+P — предыдущая, "
        "Ctrl+X — закрыть текущую, Ctrl+Q — вернуться в главное меню.[/dim]\n"
    )

    use_unix = termios is not None and sys.stdin.isatty()
    unix_fd = sys.stdin.fileno() if use_unix else -1
    unix_old: Any = None
    if use_unix:
        unix_old = termios.tcgetattr(unix_fd)
        tty.setraw(unix_fd)

    def handle_key(key: str) -> bool:
        """Обработка нажатия. Возвращает True если нужно выйти из менеджера."""
        nonlocal active_index
        session = SESSIONS[active_index]
        if key == "CTRL_N":
            active_index = (active_index + 1) % len(SESSIONS)
            console.print(f"\n[cyan]Переключение на сессию:[/cyan] {SESSIONS[active_index].title}")
        elif key == "CTRL_P":
            active_index = (active_index - 1) % len(SESSIONS)
            console.print(f"\n[cyan]Переключение на сессию:[/cyan] {SESSIONS[active_index].title}")
        elif key == "CTRL_Q":
            console.print("\n[dim]Возврат в главное меню.[/dim]")
            return True
        elif key == "CTRL_X":
            console.print(f"\n[yellow]Закрытие сессии:[/yellow] {session.title}")
            session.close()
            SESSIONS.pop(active_index)
            if not SESSIONS:
                return True
            if active_index >= len(SESSIONS):
                active_index = max(0, len(SESSIONS) - 1)
        else:
            try:
                session.channel.send(key)
            except Exception:
                session.close()
                SESSIONS.pop(active_index)
                if not SESSIONS:
                    return True
                if active_index >= len(SESSIONS):
                    active_index = max(0, len(SESSIONS) - 1)
        return False

    try:
        while SESSIONS:
            if active_index >= len(SESSIONS):
                active_index = max(0, len(SESSIONS) - 1)
            session = SESSIONS[active_index]
            session.flush_output()

            if not session.alive:
                console.print(f"\n[yellow]Сессия завершена:[/yellow] {session.title}")
                SESSIONS.pop(active_index)
                if not SESSIONS:
                    break
                continue

            key: str | None = None
            if use_unix:
                r, _, _ = select.select([sys.stdin], [], [], 0.01)
                if r:
                    ch = os.read(unix_fd, 1)
                    if ch:
                        key = _decode_control_key(ch[0], ch.decode(errors="ignore"))
            elif msvcrt is not None and msvcrt.kbhit():
                key = _read_key_windows()

            if key is not None and key != "":
                if handle_key(key):
                    return
            else:
                time.sleep(0.01)
    finally:
        if use_unix and unix_old is not None:
            termios.tcsetattr(unix_fd, termios.TCSADRAIN, unix_old)


def _attach_single_session(session: SshSession) -> None:
    try:
        while session.alive:
            session.flush_output()
            data = sys.stdin.read(1)
            if not data:
                break
            try:
                session.channel.send(data)
            except Exception:
                break
    except KeyboardInterrupt:
        console.print("\n[yellow]Отключение...[/yellow]")
    finally:
        session.close()


def connect_via_ssh(profile: Dict[str, Any]) -> None:
    session = _create_ssh_session(profile)
    if session is None:
        return

    if _multisession_available():
        SESSIONS.append(session)
        _session_manager()
    else:
        console.print("[dim]Многосессионный режим недоступен, используется одна сессия.[/dim]")
        _attach_single_session(session)


def main() -> None:
    console.print(Text("SSH Manager (многосессионная версия)", style="bold magenta"))

    while True:
        profiles = load_profiles()
        show_profiles(profiles)

        if profiles:
            console.print("\nВыберите действие:")
            console.print("  [b][1][/b] Подключиться к профилю")
            console.print("  [b][2][/b] Добавить профиль")
            if SESSIONS and _multisession_available():
                console.print("  [b][3][/b] Перейти к активным SSH-сессиям:")
                for i, sess in enumerate(SESSIONS, start=1):
                    console.print(f"      [dim]{i}.[/dim] {sess.title}")
                choices = ["0", "1", "2", "3"]
            else:
                choices = ["0", "1", "2"]
            console.print("  [b][0][/b] Выход")
            choice = IntPrompt.ask("Ваш выбор", choices=choices, default=1)
        else:
            console.print("\nНет профилей.")
            console.print("  [b][1][/b] Добавить профиль")
            if SESSIONS and _multisession_available():
                console.print("  [b][2][/b] Перейти к активным SSH-сессиям:")
                for i, sess in enumerate(SESSIONS, start=1):
                    console.print(f"      [dim]{i}.[/dim] {sess.title}")
                choices = ["0", "1", "2"]
            else:
                choices = ["0", "1"]
            console.print("  [b][0][/b] Выход")
            choice = IntPrompt.ask("Ваш выбор", choices=choices, default=1)

        if choice == 0:
            break

        if choice == 3 and profiles and SESSIONS and _multisession_available():
            _session_manager()
            continue

        if not profiles:
            if choice == 1:
                add_profile(profiles)
            elif choice == 2 and SESSIONS and _multisession_available():
                _session_manager()
            continue

        if choice == 2:
            add_profile(profiles)
            continue

        # choice == 1 и есть профили
        max_index = len(profiles)
        index = IntPrompt.ask(
            f"Номер профиля для подключения [1-{max_index}]",
            default=1,
        )
        if index < 1 or index > max_index:
            console.print("[red]Некорректный номер профиля[/red]")
            continue

        profile = profiles[index - 1]
        console.print(f"[green]Выбран профиль:[/green] {profile.get('name', '')}")

        if Confirm.ask("Подключиться сейчас?", default=True):
            connect_via_ssh(profile)


if __name__ == "__main__":
    main()

