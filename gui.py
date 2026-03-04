"""
Графический интерфейс SSH Manager на CustomTkinter.
Запуск: python gui.py
"""
import json
import os
import re
import sys
import threading
import time
from typing import Any, Callable

# Убираем ANSI-коды из вывода SSH (цвета, курсив и т.д.), чтобы текст не "плыл"
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[PX^_]")

def _strip_ansi(text: str) -> str:
    return _ANSI_ESCAPE.sub("", text)

import customtkinter as ctk
import paramiko

# Путь к данным (как в main.py)
if getattr(sys, "frozen", False):
    _BASE_DIR = os.path.dirname(sys.executable)
else:
    _BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PROFILES_FILE = os.path.join(_BASE_DIR, "profiles.json")


def load_profiles() -> list[dict[str, Any]]:
    if not os.path.exists(PROFILES_FILE):
        return []
    try:
        with open(PROFILES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def save_profiles(profiles: list[dict[str, Any]]) -> None:
    with open(PROFILES_FILE, "w", encoding="utf-8") as f:
        json.dump(profiles, f, ensure_ascii=False, indent=2)


def _load_private_key(key_path: str, passphrase: str | None = None) -> paramiko.PKey | None:
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


def connect_ssh(
    profile: dict[str, Any],
    get_password: Callable[[], str | None] | None = None,
    get_passphrase: Callable[[], str | None] | None = None,
) -> tuple[paramiko.SSHClient, paramiko.Channel] | None:
    """Подключается по профилю. Возвращает (client, channel) или None."""
    host = profile["host"]
    port = int(profile.get("port", 22))
    username = profile["username"]
    auth_type = profile.get("auth_type", "password")

    password = None
    pkey = None

    if auth_type == "password":
        password = profile.get("password") or (get_password() if get_password else None)
        if not password:
            return None
    else:
        key_path = os.path.expanduser(profile.get("key_path", ""))
        if not key_path:
            return None
        if not os.path.exists(key_path):
            return None
        key_passphrase = profile.get("key_passphrase") or (get_passphrase() if get_passphrase else None)
        try:
            pkey = _load_private_key(key_path, key_passphrase)
        except paramiko.ssh_exception.SSHException:
            pkey = _load_private_key(key_path, get_passphrase() if get_passphrase else None)
        if pkey is None:
            return None

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
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
    except Exception:
        client.close()
        return None

    channel = client.invoke_shell()
    channel.settimeout(0.0)
    return (client, channel)


class SessionView(ctk.CTkFrame):
    """Виджет SSH-сессии (вывод + поле ввода) для встраивания в основное окно."""

    def __init__(
        self,
        parent: Any,
        profile: dict[str, Any],
        client: paramiko.SSHClient,
        channel: paramiko.Channel,
        on_close: Callable[[], None],
        **kwargs: Any,
    ) -> None:
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.profile = profile
        self.client = client
        self.channel = channel
        self.on_close_cb = on_close
        self.running = True

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.text = ctk.CTkTextbox(self, font=ctk.CTkFont(family="Consolas", size=13), wrap="word")
        self.text.grid(row=0, column=0, sticky="nsew", padx=8, pady=(8, 4))

        self.entry = ctk.CTkEntry(self, placeholder_text="Введите команду...")
        self.entry.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 8))
        self.entry.bind("<Return>", self._on_send)

        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()

    def _on_send(self, event: Any = None) -> None:
        line = self.entry.get().strip() + "\n"
        self.entry.delete(0, "end")
        if not self.running:
            return
        try:
            self.channel.send(line)
        except Exception:
            self.running = False

    def _read_loop(self) -> None:
        try:
            while self.running:
                try:
                    if self.channel.recv_ready():
                        data = self.channel.recv(4096)
                        if not data:
                            break
                        text = _strip_ansi(data.decode(errors="ignore"))
                        self.after(0, lambda t=text: self._append(t))
                    else:
                        time.sleep(0.02)
                except Exception:
                    break
        finally:
            self.after(0, self._do_close)

    def _append(self, text: str) -> None:
        self.text.insert("end", text)
        self.text.see("end")

    def _do_close(self) -> None:
        self.running = False
        try:
            self.channel.close()
        except Exception:
            pass
        try:
            self.client.close()
        except Exception:
            pass
        self.on_close_cb()


class ProfileFormDialog(ctk.CTkToplevel):
    """Диалог добавления/редактирования профиля."""

    def __init__(
        self,
        parent: ctk.CTk,
        profile: dict[str, Any] | None,
        on_save: callable,
        **kwargs: Any,
    ) -> None:
        super().__init__(parent, **kwargs)
        self.profile = profile or {}
        self.on_save = on_save
        self.title("Редактирование профиля" if profile else "Новый профиль")
        self.geometry("480x420")
        self.configure(fg_color=("gray92", "gray14"))

        self.grid_columnconfigure(1, weight=1)
        row = 0

        ctk.CTkLabel(self, text="Имя:").grid(row=row, column=0, padx=10, pady=6, sticky="e")
        self.name_var = ctk.StringVar(value=self.profile.get("name", ""))
        ctk.CTkEntry(self, textvariable=self.name_var, width=280).grid(row=row, column=1, padx=10, pady=6, sticky="ew")
        row += 1

        ctk.CTkLabel(self, text="Host:").grid(row=row, column=0, padx=10, pady=6, sticky="e")
        self.host_var = ctk.StringVar(value=self.profile.get("host", ""))
        ctk.CTkEntry(self, textvariable=self.host_var, width=280).grid(row=row, column=1, padx=10, pady=6, sticky="ew")
        row += 1

        ctk.CTkLabel(self, text="Порт:").grid(row=row, column=0, padx=10, pady=6, sticky="e")
        self.port_var = ctk.StringVar(value=str(self.profile.get("port", 22)))
        ctk.CTkEntry(self, textvariable=self.port_var, width=80).grid(row=row, column=1, padx=10, pady=6, sticky="w")
        row += 1

        ctk.CTkLabel(self, text="Пользователь:").grid(row=row, column=0, padx=10, pady=6, sticky="e")
        self.user_var = ctk.StringVar(value=self.profile.get("username", ""))
        ctk.CTkEntry(self, textvariable=self.user_var, width=280).grid(row=row, column=1, padx=10, pady=6, sticky="ew")
        row += 1

        ctk.CTkLabel(self, text="Аутентификация:").grid(row=row, column=0, padx=10, pady=6, sticky="e")
        self.auth_var = ctk.StringVar(value=self.profile.get("auth_type", "password"))
        auth_frame = ctk.CTkFrame(self, fg_color="transparent")
        auth_frame.grid(row=row, column=1, padx=10, pady=6, sticky="w")
        ctk.CTkRadioButton(auth_frame, text="Пароль", variable=self.auth_var, value="password").pack(side="left", padx=(0, 20))
        ctk.CTkRadioButton(auth_frame, text="SSH-ключ", variable=self.auth_var, value="ssh_key").pack(side="left")
        row += 1

        ctk.CTkLabel(self, text="Пароль / путь к ключу:").grid(row=row, column=0, padx=10, pady=6, sticky="e")
        self.secret_var = ctk.StringVar(value=self.profile.get("password", "") or self.profile.get("key_path", ""))
        ctk.CTkEntry(self, textvariable=self.secret_var, width=280, show="*").grid(row=row, column=1, padx=10, pady=6, sticky="ew")
        row += 1

        ctk.CTkLabel(self, text="Passphrase ключа (если нужен):").grid(row=row, column=0, padx=10, pady=6, sticky="e")
        self.passphrase_var = ctk.StringVar(value=self.profile.get("key_passphrase", ""))
        ctk.CTkEntry(self, textvariable=self.passphrase_var, width=280, show="*").grid(row=row, column=1, padx=10, pady=6, sticky="ew")
        row += 1

        ctk.CTkLabel(self, text="Описание:").grid(row=row, column=0, padx=10, pady=6, sticky="e")
        self.desc_var = ctk.StringVar(value=self.profile.get("description", ""))
        ctk.CTkEntry(self, textvariable=self.desc_var, width=280).grid(row=row, column=1, padx=10, pady=6, sticky="ew")
        row += 1

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.grid(row=row, column=0, columnspan=2, pady=20)
        ctk.CTkButton(btn_frame, text="Сохранить", command=self._save).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Отмена", command=self.destroy, fg_color="gray").pack(side="left", padx=5)

        self.transient(parent)
        self.grab_set()

    def _save(self) -> None:
        try:
            port = int(self.port_var.get().strip() or "22")
        except ValueError:
            port = 22
        auth = self.auth_var.get()
        secret = self.secret_var.get().strip()
        p: dict[str, Any] = {
            "name": self.name_var.get().strip() or f"{self.user_var.get()}@{self.host_var.get()}",
            "host": self.host_var.get().strip(),
            "port": port,
            "username": self.user_var.get().strip(),
            "auth_type": auth,
            "description": self.desc_var.get().strip(),
        }
        if auth == "password":
            p["password"] = secret
            if "key_path" in p:
                del p["key_path"]
            if "key_passphrase" in p:
                del p["key_passphrase"]
        else:
            p["key_path"] = secret
            pp = self.passphrase_var.get().strip()
            if pp:
                p["key_passphrase"] = pp
            if "password" in p:
                del p["password"]
        self.on_save(p)
        self.destroy()


class MainApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("SSH Manager")
        self.geometry("820x520")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        top.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(top, text="SSH Manager", font=ctk.CTkFont(size=22, weight="bold")).grid(row=0, column=0, sticky="w")
        ctk.CTkButton(top, text="Добавить профиль", width=140, command=self._add_profile).grid(row=0, column=1, sticky="e", padx=5)

        self.content_holder = ctk.CTkFrame(self, fg_color=("gray90", "gray17"))
        self.content_holder.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 4))
        self.content_holder.grid_columnconfigure(0, weight=1)
        self.content_holder.grid_rowconfigure(0, weight=1)

        self.menu_frame = ctk.CTkScrollableFrame(self.content_holder, fg_color=("gray90", "gray17"))
        self.menu_frame.grid(row=0, column=0, sticky="nsew")
        self.menu_frame.grid_columnconfigure(1, weight=1)

        self.tab_bar = ctk.CTkFrame(self, fg_color=("gray85", "gray20"), height=44)
        self.tab_bar.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 10))
        self.tab_bar.grid_columnconfigure(0, weight=1)

        self.sessions: list[dict[str, Any]] = []
        self.current_tab: str | int = "main"

        self._refresh_list()
        self._rebuild_tabs()

    def _refresh_list(self) -> None:
        for w in self.menu_frame.winfo_children():
            w.destroy()
        profiles = load_profiles()
        if not profiles:
            ctk.CTkLabel(self.menu_frame, text="Нет профилей. Нажмите «Добавить профиль».", text_color="gray").grid(row=0, column=0, columnspan=4, pady=20)
            return
        for i, p in enumerate(profiles):
            row = ctk.CTkFrame(self.menu_frame, fg_color=("gray85", "gray22"), corner_radius=8)
            row.grid(row=i, column=0, columnspan=4, sticky="ew", padx=4, pady=4)
            row.grid_columnconfigure(1, weight=1)
            name = p.get("name", "—")
            host = p.get("host", "—")
            user = p.get("username", "—")
            auth = "ключ" if p.get("auth_type") == "ssh_key" else "пароль"
            ctk.CTkLabel(row, text=name, font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=12, pady=8, sticky="w")
            ctk.CTkLabel(row, text=f"{user}@{host}", text_color="gray").grid(row=0, column=1, padx=8, pady=8, sticky="w")
            ctk.CTkLabel(row, text=auth, text_color="gray", width=50).grid(row=0, column=2, padx=4, pady=8)
            ctk.CTkButton(row, text="Подключиться", width=120, command=lambda pr=p: self._connect(pr)).grid(row=0, column=3, padx=6, pady=6)
            ctk.CTkButton(row, text="Изменить", width=80, fg_color="gray", command=lambda pr=p: self._edit(pr)).grid(row=0, column=4, padx=2, pady=6)
            ctk.CTkButton(row, text="Удалить", width=70, fg_color="#c42b2b", command=lambda pr=p: self._delete(pr)).grid(row=0, column=5, padx=6, pady=6)

    def _rebuild_tabs(self) -> None:
        for w in self.tab_bar.winfo_children():
            w.destroy()
        tabs_frame = ctk.CTkFrame(self.tab_bar, fg_color="transparent")
        tabs_frame.pack(side="left", fill="y", padx=6, pady=6)
        main_btn = ctk.CTkButton(
            tabs_frame, text="Главное меню", width=120, height=28,
            fg_color=("#2b5278", "#2b5278") if self.current_tab == "main" else ("gray65", "gray35"),
            command=self._switch_to_main,
        )
        main_btn.pack(side="left", padx=2)
        for i, s in enumerate(self.sessions):
            title = s["profile"].get("name", "Сессия")
            btn = ctk.CTkButton(
                tabs_frame, text=title, width=120, height=28,
                fg_color=("#2b5278", "#2b5278") if self.current_tab == i else ("gray65", "gray35"),
                command=lambda idx=i: self._switch_to_session(idx),
            )
            btn.pack(side="left", padx=2)
            s["tab_btn"] = btn

    def _switch_to_main(self) -> None:
        self.current_tab = "main"
        self.menu_frame.lift()
        self._rebuild_tabs()

    def _switch_to_session(self, index: int) -> None:
        if 0 <= index < len(self.sessions):
            self.current_tab = index
            self.sessions[index]["view"].lift()
            self._rebuild_tabs()

    def _on_session_closed(self, index: int) -> None:
        if index < 0 or index >= len(self.sessions):
            return
        was_current = self.current_tab == index
        s = self.sessions.pop(index)
        s["view"].destroy()
        if was_current:
            self.current_tab = "main"
            self.menu_frame.lift()
        elif isinstance(self.current_tab, int) and self.current_tab > index:
            self.current_tab -= 1
        self._rebuild_tabs()

    def _add_profile(self) -> None:
        def on_save(p: dict[str, Any]) -> None:
            profiles = load_profiles()
            profiles.append(p)
            save_profiles(profiles)
            self._refresh_list()

        d = ProfileFormDialog(self, None, on_save)
        d.focus()

    def _edit(self, profile: dict[str, Any]) -> None:
        profiles = load_profiles()
        idx = next((i for i, x in enumerate(profiles) if x.get("name") == profile.get("name") and x.get("host") == profile.get("host")), None)
        if idx is None:
            return

        def on_save(p: dict[str, Any]) -> None:
            profiles = load_profiles()
            if idx < len(profiles):
                profiles[idx] = p
                save_profiles(profiles)
                self._refresh_list()

        ProfileFormDialog(self, profiles[idx], on_save)

    def _delete(self, profile: dict[str, Any]) -> None:
        profiles = load_profiles()
        profiles = [x for x in profiles if not (x.get("name") == profile.get("name") and x.get("host") == profile.get("host"))]
        save_profiles(profiles)
        self._refresh_list()

    def _connect(self, profile: dict[str, Any]) -> None:
        auth_type = profile.get("auth_type", "password")
        get_password: Callable[[], str | None] | None = None
        get_passphrase: Callable[[], str | None] | None = None
        if auth_type == "password" and not profile.get("password"):
            def _ask_password() -> str:
                d = ctk.CTkInputDialog(text="Введите пароль:", title="Пароль")
                return d.get_input() or ""
            get_password = _ask_password
        if auth_type == "ssh_key":
            key_path = os.path.expanduser(profile.get("key_path", ""))
            if not key_path or not os.path.exists(key_path):
                self._show_error("Ключ не найден", f"Путь: {key_path}")
                return
            if profile.get("key_passphrase") is None:
                def _ask_passphrase() -> str:
                    d = ctk.CTkInputDialog(text="Passphrase для ключа (если не защищён — оставьте пусто):", title="Passphrase")
                    return d.get_input() or ""
                get_passphrase = _ask_passphrase

        result = connect_ssh(profile, get_password, get_passphrase)
        if result is None:
            self._show_error("Ошибка подключения", "Проверьте хост, логин, пароль или ключ.")
            return
        client, channel = result

        view = SessionView(
            self.content_holder,
            profile,
            client,
            channel,
            on_close=lambda: None,
        )
        view.grid(row=0, column=0, sticky="nsew")

        def close_cb() -> None:
            for i, s in enumerate(self.sessions):
                if s.get("view") is view:
                    self._on_session_closed(i)
                    return
        view.on_close_cb = close_cb

        self.sessions.append({"profile": profile, "client": client, "channel": channel, "view": view, "tab_btn": None})
        self._rebuild_tabs()
        self._switch_to_session(len(self.sessions) - 1)

    def _show_error(self, title: str, message: str) -> None:
        d = ctk.CTkToplevel(self)
        d.title(title)
        d.geometry("400x120")
        d.transient(self)
        ctk.CTkLabel(d, text=message, wraplength=360).pack(padx=20, pady=20)
        ctk.CTkButton(d, text="OK", command=d.destroy).pack(pady=(0, 15))


def main() -> None:
    app = MainApp()
    app.mainloop()


if __name__ == "__main__":
    main()
