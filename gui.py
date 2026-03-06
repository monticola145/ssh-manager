"""
Графический интерфейс SSH Manager на CustomTkinter.
Запуск: python gui.py
"""
import json
import os
import queue
import re
import sys
import threading
import time
from typing import Any, Callable

# ANSI SGR → имя тега для подсветки (тёмная тема)
_ANSI_FG_TAGS = {
    30: "ansi_black",
    31: "ansi_red",
    32: "ansi_green",
    33: "ansi_yellow",
    34: "ansi_blue",
    35: "ansi_magenta",
    36: "ansi_cyan",
    37: "ansi_white",
    90: "ansi_bright_black",
    91: "ansi_bright_red",
    92: "ansi_bright_green",
    93: "ansi_bright_yellow",
    94: "ansi_bright_blue",
    95: "ansi_bright_magenta",
    96: "ansi_bright_cyan",
    97: "ansi_bright_white",
}

def _parse_ansi(chunk: str) -> list[tuple[str, str]]:
    """Разбирает строку с ANSI-кодами, возвращает список (текст, имя_тега)."""
    out: list[tuple[str, str]] = []
    current = "default"
    i = 0
    while i < len(chunk):
        if chunk[i : i + 1] == "\x1b" and i + 1 < len(chunk):
            if chunk[i + 1] == "[":
                j = i + 2
                while j < len(chunk) and chunk[j] not in "ABCDEFGHJKRm":
                    j += 1
                if j < len(chunk) and chunk[j] == "m":
                    codes = chunk[i + 2 : j]
                    for part in codes.split(";"):
                        try:
                            n = int(part.strip())
                            if n == 0 or n == 39:
                                current = "default"
                            elif n in _ANSI_FG_TAGS:
                                current = _ANSI_FG_TAGS[n]
                        except ValueError:
                            pass
                i = j + 1
                continue
            if chunk[i + 1] == "]":
                j = chunk.find("\x07", i + 2)
                if j != -1:
                    i = j + 1
                    continue
        # обычный текст до следующего ESC
        end = chunk.find("\x1b", i)
        if end == -1:
            end = len(chunk)
        if end > i:
            out.append((chunk[i:end], current))
        i = end
    return out


def _key_event_to_bytes(event: Any) -> bytes:
    """Преобразует событие клавиши Tk в байты для отправки в PTY (nano, vim)."""
    char = getattr(event, "char", "") or ""
    keysym = getattr(event, "keysym", "")
    state = getattr(event, "state", 0)
    # Один символ (в т.ч. управляющий при Ctrl+буква)
    if len(char) == 1:
        o = ord(char)
        if o < 32 or o == 127:
            return bytes([o])
        return char.encode("utf-8")
    # Специальные клавиши
    key_to_bytes: dict[str, bytes] = {
        "Return": b"\r",
        "KP_Enter": b"\r",
        "BackSpace": b"\x7f",
        "Tab": b"\t",
        "Left": b"\x1b[D",
        "Right": b"\x1b[C",
        "Up": b"\x1b[A",
        "Down": b"\x1b[B",
        "Home": b"\x1b[H",
        "End": b"\x1b[F",
        "Delete": b"\x1b[3~",
    }
    if keysym in key_to_bytes:
        return key_to_bytes[keysym]
    # Ctrl+символ по keysym (когда char пустой)
    if state & 0x4 and keysym:
        if len(keysym) == 1 and "a" <= keysym <= "z":
            return bytes([ord(keysym.upper()) - 64])
        if len(keysym) == 1 and "A" <= keysym <= "Z":
            return bytes([ord(keysym) - 64])
        if keysym in ("slash", "question"):
            return b"\x1f"  # Ctrl+/
        if keysym == "bracketleft":
            return b"\x1b"  # Ctrl+[
        if keysym == "backslash":
            return b"\x1c"  # Ctrl+\
    return b""


import customtkinter as ctk
import paramiko

try:
    import pyte
    from wcwidth import wcwidth
except ImportError:
    pyte = None  # pip install pyte
    wcwidth = None

# Цвета pyte (имена fg/bg) → hex для тёмной темы терминала
_PYTE_COLORS: dict[str, str] = {
    "default": "#abb2bf",
    "black": "#5c6370",
    "red": "#e06c75",
    "green": "#98c379",
    "brown": "#e5c07b",
    "blue": "#61afef",
    "magenta": "#c678dd",
    "cyan": "#56b6c2",
    "white": "#abb2bf",
    "brightblack": "#4b5263",
    "brightred": "#e06c75",
    "brightgreen": "#98c379",
    "brightbrown": "#e5c07b",
    "brightblue": "#61afef",
    "brightmagenta": "#c678dd",
    "brightcyan": "#56b6c2",
    "brightwhite": "#c8ccd4",
}

# Путь к данным (как в main.py)
if getattr(sys, "frozen", False):
    _BASE_DIR = os.path.dirname(sys.executable)
else:
    _BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PROFILES_FILE = os.path.join(_BASE_DIR, "profiles.json")
NOTES_FILE = os.path.join(_BASE_DIR, "notes.txt")


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


def load_notes() -> str:
    if not os.path.exists(NOTES_FILE):
        return ""
    try:
        with open(NOTES_FILE, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def save_notes(text: str) -> None:
    try:
        with open(NOTES_FILE, "w", encoding="utf-8") as f:
            f.write(text)
    except OSError:
        pass


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

    channel = client.invoke_shell(term="xterm", width=80, height=24)
    channel.settimeout(0.0)
    return (client, channel)


def _setup_pyte_tags(textbox: Any) -> None:
    """Настраивает теги виджета текста под цвета pyte (тёмная тема)."""
    for name, hex_color in _PYTE_COLORS.items():
        tag = "pyte_" + name
        textbox.tag_configure(tag, foreground=hex_color)


def _screen_to_segments(screen: Any) -> list[tuple[str, str]]:
    """Собирает из буфера pyte Screen список пар (текст, имя_тега) с учётом wide-символов."""
    segments: list[tuple[str, str]] = []
    cols, lines = screen.columns, screen.lines
    for y in range(lines):
        row = screen.buffer[y]
        is_wide = False
        for x in range(cols):
            if is_wide:
                is_wide = False
                continue
            ch = row[x]
            data = ch.data
            fg = ch.bg if ch.reverse else ch.fg
            tag = "pyte_" + (fg if fg in _PYTE_COLORS else "default")
            if wcwidth is not None and data:
                if wcwidth(data[0]) == 2:
                    is_wide = True
            segments.append((data, tag))
        if y < lines - 1:
            segments.append(("\n", "pyte_default"))
    return segments


class SessionView(ctk.CTkFrame):
    """Виджет SSH-сессии (встроенный терминал на pyte) для встраивания в основное окно."""

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
        if pyte is None:
            raise ImportError("Для встроенного терминала нужен pyte. Выполните: pip install pyte")

        self.profile = profile
        self.client = client
        self.channel = channel
        self.on_close_cb = on_close
        self.running = True

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._term_cols, self._term_rows = 80, 24
        self._screen = pyte.Screen(self._term_cols, self._term_rows)
        self._stream = pyte.ByteStream(self._screen)

        self.text = ctk.CTkTextbox(
            self,
            font=ctk.CTkFont(family="Consolas", size=13),
            wrap="none",
        )
        self.text.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        _setup_pyte_tags(self.text._textbox)

        self.text.bind("<Control-c>", self._on_ctrl_c)
        self.text.bind("<Control-v>", self._on_ctrl_v)
        self.text._textbox.bind("<KeyPress>", self._on_terminal_key)

        self._output_queue: queue.Queue[bytes] = queue.Queue()
        self._output_schedule_id: str | None = None
        self._flush_interval_ms = 40

        self._send_queue: queue.Queue[bytes] = queue.Queue()
        self._sender_thread = threading.Thread(target=self._send_loop, daemon=True)
        self._sender_thread.start()

        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()
        self.after(self._flush_interval_ms, self._poll_pending_output)

    def _on_ctrl_c(self, event: Any = None) -> str:
        try:
            sel = self.text._textbox.get("sel.first", "sel.last")
            if sel:
                root = self.winfo_toplevel()
                root.clipboard_clear()
                root.clipboard_append(sel)
                return "break"
        except Exception:
            pass
        if self.running:
            self._send(b"\x03")
        return "break"

    def _on_ctrl_v(self, event: Any = None) -> str:
        try:
            root = self.winfo_toplevel()
            paste_text = root.clipboard_get()
            if paste_text and self.running:
                self._send(paste_text)
        except Exception:
            pass
        return "break"

    def _send_loop(self) -> None:
        while self.running:
            try:
                data = self._send_queue.get(timeout=0.05)
                if not self.running:
                    break
                self.channel.send(data)
            except queue.Empty:
                continue
            except Exception:
                break

    def _send(self, data: bytes | str) -> None:
        if not self.running:
            return
        b = data.encode("utf-8") if isinstance(data, str) else data
        try:
            self._send_queue.put_nowait(b)
        except queue.Full:
            pass

    def _on_terminal_key(self, event: Any) -> str:
        if not self.running:
            return "break"
        state = getattr(event, "state", 0)
        keysym = getattr(event, "keysym", "")
        if (state & 0x4) and keysym.lower() == "v":
            try:
                root = self.winfo_toplevel()
                paste_text = root.clipboard_get()
                if paste_text:
                    self._send(paste_text)
            except Exception:
                pass
            return "break"
        data = _key_event_to_bytes(event)
        if data:
            self._send(data)
        return "break"

    def _read_loop(self) -> None:
        try:
            while self.running:
                try:
                    if self.channel.recv_ready():
                        data = self.channel.recv(4096)
                        if not data:
                            break
                        try:
                            self._output_queue.put_nowait(data)
                        except queue.Full:
                            pass
                    else:
                        time.sleep(0.02)
                except Exception:
                    break
        finally:
            self.after(0, self._connection_lost)

    def _connection_lost(self) -> None:
        """Сервер закрыл соединение (exit и т.п.). Закрываем канал/клиент, вкладку не закрываем."""
        self.running = False
        try:
            self.channel.close()
        except Exception:
            pass
        try:
            self.client.close()
        except Exception:
            pass

    def disconnect(self) -> None:
        """Отключиться по запросу пользователя (крестик на вкладке). Останавливает потоки и закрывает канал/клиент."""
        self.running = False
        try:
            self.channel.close()
        except Exception:
            pass
        try:
            self.client.close()
        except Exception:
            pass

    def _do_close(self) -> None:
        """Полное закрытие с вызовом on_close_cb (сейчас не используется — вкладка закрывается только по крестику)."""
        self.disconnect()
        self.on_close_cb()

    def _poll_pending_output(self) -> None:
        if not self.running:
            return
        if self._output_queue.empty():
            self._output_schedule_id = None
            self.after(self._flush_interval_ms, self._poll_pending_output)
            return
        if self._output_schedule_id is not None:
            self.after(self._flush_interval_ms, self._poll_pending_output)
            return
        self._output_schedule_id = "scheduled"
        self._flush_pending_output()
        self.after(self._flush_interval_ms, self._poll_pending_output)

    def _flush_pending_output(self) -> None:
        chunks: list[bytes] = []
        total = 0
        max_bytes = 65536
        while total < max_bytes:
            try:
                data = self._output_queue.get_nowait()
                chunks.append(data)
                total += len(data)
            except queue.Empty:
                break
        self._output_schedule_id = None
        if chunks:
            try:
                self._stream.feed(b"".join(chunks))
            except Exception:
                pass
        segments = _screen_to_segments(self._screen)
        self.text._textbox.delete("1.0", "end")
        for text, tag in segments:
            self.text._textbox.insert("end", text, tag)
        # Курсор виджета — в позиции курсора терминала (pyte), а не в конце текста
        cy = max(0, min(self._screen.cursor.y, self._term_rows - 1))
        cx = max(0, min(self._screen.cursor.x, self._term_cols))
        insert_offset = cy * (self._term_cols + 1) + cx
        self.text._textbox.mark_set("insert", f"1.0+{insert_offset}c")
        self.text._textbox.see("insert")
        if not self._output_queue.empty():
            self._output_schedule_id = "scheduled"
            self.after(self._flush_interval_ms, self._flush_pending_output)

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
        self._main_width = 820
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self._main_width = 820
        self._notepad_strip_w = 24
        self._notepad_collapsed_w = 24
        self._notepad_expanded_w = 416
        self._main_right_pad = 0
        self.grid_columnconfigure(0, weight=0, minsize=self._main_width)
        self.grid_columnconfigure(1, weight=0)
        self.grid_rowconfigure(1, weight=1)

        self._left_frame = ctk.CTkFrame(self, width=self._main_width, fg_color="transparent")
        self._left_frame.grid(row=0, column=0, rowspan=3, sticky="nsew", padx=(0, self._main_right_pad))
        self._left_frame.grid_propagate(False)
        self._left_frame.grid_columnconfigure(0, weight=1)
        self._left_frame.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(self._left_frame, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        top.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(top, text="SSH Manager", font=ctk.CTkFont(size=22, weight="bold")).grid(row=0, column=0, sticky="w")
        ctk.CTkButton(top, text="Добавить профиль", width=140, command=self._add_profile).grid(row=0, column=1, sticky="e", padx=5)

        self.content_holder = ctk.CTkFrame(self._left_frame, fg_color=("gray90", "gray17"))
        self.content_holder.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 4))
        self.content_holder.grid_columnconfigure(0, weight=1)
        self.content_holder.grid_rowconfigure(0, weight=1)

        self.menu_frame = ctk.CTkScrollableFrame(self.content_holder, fg_color=("gray90", "gray17"))
        self.menu_frame.grid(row=0, column=0, sticky="nsew")
        self.menu_frame.grid_columnconfigure(1, weight=1)

        self._left_frame.grid_rowconfigure(2, minsize=48)
        self.tab_bar = ctk.CTkFrame(self._left_frame, fg_color=("gray85", "gray20"), height=44)
        self.tab_bar.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 10))
        self.tab_bar.grid_propagate(False)
        self.tab_bar.grid_columnconfigure(0, weight=1)

        self.sessions: list[dict[str, Any]] = []
        self.current_tab: str | int = "main"

        self._notepad_expanded = False
        self._notes_save_after_id: str | None = None
        self._right_panel = ctk.CTkFrame(self, width=self._notepad_collapsed_w, fg_color=("gray88", "gray22"))
        self._right_panel.grid(row=0, column=1, rowspan=3, sticky="ns", padx=(0, 6), pady=10)
        self._right_panel.grid_propagate(False)
        self._build_notepad_collapsed()
        self.geometry(f"{self._main_width + self._main_right_pad + self._notepad_collapsed_w}x520")

        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._refresh_list()
        self._rebuild_tabs()

    def _build_notepad_collapsed(self) -> None:
        for w in self._right_panel.winfo_children():
            w.destroy()
        self._right_panel.configure(width=self._notepad_collapsed_w)
        btn = ctk.CTkButton(
            self._right_panel,
            text="▶",
            width=20,
            height=60,
            fg_color="transparent",
            command=self._toggle_notepad,
        )
        btn.pack(expand=True, pady=16)

    def _build_notepad_expanded(self) -> None:
        for w in self._right_panel.winfo_children():
            w.destroy()
        total_w = self._notepad_strip_w + self._notepad_expanded_w
        self._right_panel.configure(width=total_w)
        try:
            geom = self.geometry()
            h = 520
            if "+" in geom:
                parts = geom.split("+")
                _, h = map(int, parts[0].split("x"))
                x, y = int(parts[1]), int(parts[2]) if len(parts) > 2 else 0
                self.geometry(f"{self._main_width + self._main_right_pad + total_w}x{h}+{x}+{y}")
            else:
                _, h = map(int, geom.split("x"))
                self.geometry(f"{self._main_width + self._main_right_pad + total_w}x{h}")
        except Exception:
            self.geometry(f"{self._main_width + self._main_right_pad + total_w}x520")

        strip = ctk.CTkFrame(self._right_panel, width=self._notepad_strip_w, fg_color=("gray88", "gray22"))
        strip.pack(side="left", fill="y")
        strip.pack_propagate(False)
        ctk.CTkButton(
            strip,
            text="◀",
            width=20,
            height=60,
            fg_color="transparent",
            command=self._toggle_notepad,
        ).pack(expand=True, pady=16)

        notes_frame = ctk.CTkFrame(self._right_panel, width=self._notepad_expanded_w, fg_color="transparent")
        notes_frame.pack(side="left", fill="y", padx=(0, 6), pady=6)
        notes_frame.pack_propagate(False)
        ctk.CTkLabel(notes_frame, text="Блокнот", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=4, pady=(0, 4))

        self._notes_textbox = ctk.CTkTextbox(notes_frame, font=ctk.CTkFont(size=13), wrap="word")
        self._notes_textbox.pack(fill="both", expand=True, pady=(0, 6))
        self._notes_textbox.insert("1.0", load_notes())
        self._notes_textbox.bind("<KeyRelease>", self._notes_schedule_save)

    def _toggle_notepad(self) -> None:
        if self._notepad_expanded:
            self._save_notes_now()
            self._notepad_expanded = False
            try:
                geom = self.geometry()
                h = 520
                if "+" in geom:
                    parts = geom.split("+")
                    _, h = map(int, parts[0].split("x"))
                    x, y = int(parts[1]), int(parts[2]) if len(parts) > 2 else 0
                    self.geometry(f"{self._main_width + self._main_right_pad + self._notepad_collapsed_w}x{h}+{x}+{y}")
                else:
                    _, h = map(int, geom.split("x"))
                    self.geometry(f"{self._main_width + self._main_right_pad + self._notepad_collapsed_w}x{h}")
            except Exception:
                self.geometry(f"{self._main_width + self._main_right_pad + self._notepad_collapsed_w}x520")
            self._build_notepad_collapsed()
        else:
            self._notepad_expanded = True
            self._build_notepad_expanded()

    def _notes_schedule_save(self, event: Any = None) -> None:
        if self._notes_save_after_id:
            self.after_cancel(self._notes_save_after_id)
        self._notes_save_after_id = self.after(800, self._notes_do_save)

    def _notes_do_save(self) -> None:
        self._notes_save_after_id = None
        if self._notepad_expanded and hasattr(self, "_notes_textbox"):
            try:
                text = self._notes_textbox.get("1.0", "end-1c")
                save_notes(text)
            except Exception:
                pass

    def _save_notes_now(self) -> None:
        if self._notes_save_after_id:
            self.after_cancel(self._notes_save_after_id)
            self._notes_save_after_id = None
        if self._notepad_expanded and hasattr(self, "_notes_textbox"):
            try:
                text = self._notes_textbox.get("1.0", "end-1c")
                save_notes(text)
            except Exception:
                pass

    def _on_close(self) -> None:
        self._save_notes_now()
        self.destroy()

    def _refresh_list(self) -> None:
        for w in self.menu_frame.winfo_children():
            w.destroy()
        profiles = load_profiles()
        if not profiles:
            ctk.CTkLabel(self.menu_frame, text="Нет профилей. Нажмите «Добавить профиль».", text_color="gray").grid(row=0, column=0, columnspan=4, pady=20)
            return
        for i, p in enumerate(profiles):
            row = ctk.CTkFrame(self.menu_frame, fg_color=("gray85", "gray22"), corner_radius=8)
            row.grid(row=i, column=0, columnspan=6, sticky="ew", padx=4, pady=4)
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
        tab_row = ctk.CTkFrame(self.tab_bar, fg_color="transparent")
        tab_row.pack(fill="x", expand=True, padx=6, pady=6)

        tab_height = 28

        main_btn = ctk.CTkButton(
            tab_row,
            text="Главное меню",
            width=120,
            height=tab_height,
            fg_color=("#2b5278", "#2b5278") if self.current_tab == "main" else ("gray65", "gray35"),
            command=self._switch_to_main,
        )
        main_btn.pack(side="left", padx=2)

        for i, s in enumerate(self.sessions):
            title = s["profile"].get("name", "Сессия")
            is_active = self.current_tab == i
            tab_bg = ("#2b5278", "#2b5278") if is_active else ("gray65", "gray35")
            tab_fg = ("gray90", "gray90")

            tab_frame = ctk.CTkFrame(tab_row, fg_color=tab_bg, corner_radius=6, width=130, height=tab_height)
            tab_frame.pack(side="left", padx=2)
            tab_frame.pack_propagate(False)
            tab_frame.grid_columnconfigure(1, weight=1)
            tab_frame.grid_rowconfigure(0, weight=1)
            tab_frame.bind("<Button-1>", lambda e, idx=i: self._switch_to_session(idx))

            lbl = ctk.CTkLabel(tab_frame, text=title, text_color=tab_fg, anchor="w")
            lbl.grid(row=0, column=0, sticky="w", padx=(10, 4), pady=0)
            lbl.bind("<Button-1>", lambda e, idx=i: self._switch_to_session(idx))

            close_lbl = ctk.CTkLabel(tab_frame, text=" ✕ ", text_color=tab_fg, cursor="hand2")
            close_lbl.grid(row=0, column=1, sticky="e", padx=(0, 8), pady=0)

            def _close_tab(e: Any, idx: int = i) -> str:
                self._on_session_closed(idx)
                return "break"

            close_lbl.bind("<Button-1>", _close_tab)

            s["tab_btn"] = tab_frame

    def _switch_to_main(self) -> None:
        self.current_tab = "main"
        for s in self.sessions:
            s["view"].grid_remove()
        self.menu_frame.grid(row=0, column=0, sticky="nsew")
        self._rebuild_tabs()

    def _switch_to_session(self, index: int) -> None:
        if 0 <= index < len(self.sessions):
            self.current_tab = index
            self.menu_frame.grid_remove()
            for i, s in enumerate(self.sessions):
                if i == index:
                    s["view"].grid(row=0, column=0, sticky="nsew")
                else:
                    s["view"].grid_remove()
            self._rebuild_tabs()

    def _on_session_closed(self, index: int) -> None:
        if index < 0 or index >= len(self.sessions):
            return
        was_current = self.current_tab == index
        s = self.sessions.pop(index)
        s["view"].disconnect()
        s["view"].destroy()
        if was_current:
            self.current_tab = "main"
            for v in self.sessions:
                v["view"].grid_remove()
            self.menu_frame.grid(row=0, column=0, sticky="nsew")
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

        try:
            view = SessionView(
                self.content_holder,
                profile,
                client,
                channel,
                on_close=lambda: None,
            )
        except Exception as e:
            self._show_error("Ошибка терминала", str(e))
            try:
                channel.close()
                client.close()
            except Exception:
                pass
            return

        self.menu_frame.grid_remove()
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
