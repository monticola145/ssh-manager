import json
import os
import sys
import threading
from typing import List, Dict, Any

import paramiko
from rich.console import Console
from rich.table import Table
from rich.prompt import IntPrompt, Confirm
from rich.text import Text


console = Console()


PROFILES_FILE = os.path.join(os.path.dirname(__file__), "profiles.json")


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

    profiles.append(profile)
    save_profiles(profiles)
    console.print("[green]Профиль сохранён.[/green]")


def connect_via_ssh(profile: Dict[str, Any]) -> None:
    host = profile["host"]
    port = profile.get("port", 22)
    username = profile["username"]
    auth_type = profile.get("auth_type", "password")

    password = None
    pkey = None

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
            return
        try:
            pkey = paramiko.RSAKey.from_private_key_file(key_path)
        except Exception as e:
            console.print(f"[red]Ошибка чтения ключа: {e}[/red]")
            return

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
        return

    console.print("[green]Подключено. Открывается интерактивная сессия SSH.[/green]")
    console.print("[dim]Для выхода используйте команды удалённой системы или закройте окно.[/dim]")

    channel = client.invoke_shell()
    channel.settimeout(0.0)

    def read_from_server() -> None:
        try:
            while True:
                if channel.recv_ready():
                    try:
                        data = channel.recv(4096)
                    except Exception:
                        break
                    if not data:
                        break
                    sys.stdout.write(data.decode(errors="ignore"))
                    sys.stdout.flush()
        finally:
            client.close()

    def write_to_server() -> None:
        try:
            while True:
                data = sys.stdin.read(1)
                if not data:
                    break
                try:
                    channel.send(data)
                except Exception:
                    break
        finally:
            try:
                channel.close()
            except Exception:
                pass

    reader = threading.Thread(target=read_from_server, daemon=True)
    writer = threading.Thread(target=write_to_server, daemon=True)

    reader.start()
    writer.start()

    try:
        reader.join()
        writer.join()
    except KeyboardInterrupt:
        console.print("\n[yellow]Отключение...[/yellow]")
    finally:
        try:
            channel.close()
        except Exception:
            pass
        client.close()


def main() -> None:
    console.print(Text("SSH Manager (минимальная версия)", style="bold magenta"))

    while True:
        profiles = load_profiles()
        show_profiles(profiles)

        if profiles:
            console.print("\nВыберите действие:")
            console.print("  [b][1][/b] Подключиться к профилю")
            console.print("  [b][2][/b] Добавить профиль")
            console.print("  [b][0][/b] Выход")
            choice = IntPrompt.ask("Ваш выбор", choices=["0", "1", "2"], default=1)
        else:
            console.print("\nНет профилей.")
            console.print("  [b][1][/b] Добавить профиль")
            console.print("  [b][0][/b] Выход")
            choice = IntPrompt.ask("Ваш выбор", choices=["0", "1"], default=1)

        if choice == 0:
            break

        if not profiles:
            if choice == 1:
                add_profile(profiles)
            continue

        if choice == 2:
            add_profile(profiles)
            continue

        # choice == 1 and there are profiles
        if not profiles:
            console.print("[red]Профили отсутствуют.[/red]")
            continue

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

