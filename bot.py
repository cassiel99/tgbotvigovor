import asyncio
import logging
import os
import re
import sqlite3
from contextlib import closing
from datetime import datetime
from types import SimpleNamespace

from aiogram import Bot, Dispatcher, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command, CommandStart
from aiogram.filters.command import CommandObject
from aiogram.types import BotCommand, Message, MessageEntity
from dotenv import load_dotenv

# =========================
# Настройки доступа (Whitelist)
# =========================
ALLOWED_USER_IDS = {
    578664673,
    921799469,
    5253999365,
    824111058,
}

def is_allowed(user_id: int | None) -> bool:
    return user_id in ALLOWED_USER_IDS if user_id is not None else False

# =========================
# Конфигурация и БД
# =========================

DB_PATH = "warns.sqlite3"

def db_init():
    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS warns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                user_name TEXT,
                warn_type TEXT CHECK (warn_type IN ('warn','hard')) NOT NULL,
                reason TEXT,
                given_by_id INTEGER,
                given_by_name TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS participants (
                chat_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                username TEXT,
                username_lower TEXT,
                first_name TEXT,
                last_name TEXT,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (chat_id, user_id)
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_participants_chat_username ON participants (chat_id, username_lower)"
        )

def participant_upsert(chat_id: int, user) -> None:
    if user is None:
        return
    username = user.username or None
    username_lower = (username or "").lower() or None
    first_name = user.first_name or None
    last_name = user.last_name or None
    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
        conn.execute(
            """
            INSERT INTO participants (chat_id, user_id, username, username_lower, first_name, last_name, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(chat_id, user_id) DO UPDATE SET
                username=excluded.username,
                username_lower=excluded.username_lower,
                first_name=excluded.first_name,
                last_name=excluded.last_name,
                updated_at=excluded.updated_at
            """,
            (
                chat_id, user.id, username, username_lower, first_name, last_name,
                datetime.utcnow().isoformat(),
            ),
        )

def find_participant_by_username(chat_id: int, username_lower: str):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cur = conn.execute(
            """
            SELECT user_id, username, first_name, last_name
            FROM participants
            WHERE chat_id = ? AND username_lower = ?
            """,
            (chat_id, username_lower),
        )
        row = cur.fetchone()
        if not row:
            return None
        user_id, username, first_name, last_name = row
        full_name = " ".join([x for x in [first_name, last_name] if x]) or (f"@{username}" if username else "user")
        return SimpleNamespace(id=user_id, full_name=full_name)

def add_warn(
    chat_id: int,
    user_id: int,
    user_name: str,
    warn_type: str,
    reason: str | None,
    given_by_id: int | None,
    given_by_name: str | None,
):
    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
        conn.execute(
            """
            INSERT INTO warns (chat_id, user_id, user_name, warn_type, reason, given_by_id, given_by_name, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                chat_id,
                user_id,
                user_name,
                warn_type,
                reason or "",
                given_by_id,
                given_by_name,
                datetime.utcnow().isoformat(),
            ),
        )

def get_user_warns(chat_id: int, user_id: int):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cur = conn.execute(
            """
            SELECT id, warn_type, reason, created_at, given_by_name
            FROM warns
            WHERE chat_id = ? AND user_id = ?
            ORDER BY created_at DESC, id DESC
            """,
            (chat_id, user_id),
        )
        return cur.fetchall()

def get_user_counts(chat_id: int, user_id: int):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cur = conn.execute(
            """
            SELECT warn_type, COUNT(*)
            FROM warns
            WHERE chat_id = ? AND user_id = ?
            GROUP BY warn_type
            """,
            (chat_id, user_id),
        )
        data = {row[0]: row[1] for row in cur.fetchall()}
    return data.get("warn", 0), data.get("hard", 0)

def get_all_counts(chat_id: int):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cur = conn.execute(
            """
            SELECT user_id,
                   COALESCE(MAX(user_name), '') as user_name,
                   SUM(CASE WHEN warn_type='warn' THEN 1 ELSE 0 END) as warn_cnt,
                   SUM(CASE WHEN warn_type='hard' THEN 1 ELSE 0 END) as hard_cnt
            FROM warns
            WHERE chat_id = ?
            GROUP BY user_id
            ORDER BY (warn_cnt + hard_cnt) DESC, hard_cnt DESC
            """,
            (chat_id,),
        )
        return cur.fetchall()

def amnesty_partial(chat_id: int, user_id: int, count: int, kind: str):
    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
        if kind in ("warn", "hard"):
            conn.execute(
                """
                DELETE FROM warns
                WHERE id IN (
                    SELECT id FROM warns
                    WHERE chat_id = ? AND user_id = ? AND warn_type = ?
                    ORDER BY created_at DESC, id DESC
                    LIMIT ?
                )
                """,
                (chat_id, user_id, kind, count),
            )
        else:
            conn.execute(
                """
                DELETE FROM warns
                WHERE id IN (
                    SELECT id FROM warns
                    WHERE chat_id = ? AND user_id = ?
                    ORDER BY created_at DESC, id DESC
                    LIMIT ?
                )
                """,
                (chat_id, user_id, count),
            )

def amnesty_full(chat_id: int, user_id: int):
    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
        conn.execute(
            "DELETE FROM warns WHERE chat_id = ? AND user_id = ?",
            (chat_id, user_id),
        )

# =========================
# Утилиты
# =========================

async def is_admin(bot: Bot, chat_id: int, user_id: int) -> bool:
    try:
        member = await bot.get_chat_member(chat_id, user_id)
        return member.status in {"administrator", "creator"}
    except TelegramBadRequest:
        return False

def html_user_link(user_id: int, name: str | None) -> str:
    safe = (name or "user").replace("<", "&lt;").replace(">", "&gt;")
    return f'<a href="tg://user?id={user_id}">{safe}</a>'

def track_message_participants(message: Message):
    # Автор
    if message.from_user:
        participant_upsert(message.chat.id, message.from_user)
    # Адресат в ответе
    if message.reply_to_message and message.reply_to_message.from_user:
        participant_upsert(message.chat.id, message.reply_to_message.from_user)

def extract_mention_username(message: Message) -> str | None:
    """
    Возвращает username без '@' из последнего mention в сообщении.
    Поддерживается обычное упоминание вида @user (entity.type == 'mention').
    """
    if not message.entities:
        return None
    text = message.text or message.caption or ""
    mentions = []
    for ent in message.entities:
        if isinstance(ent, MessageEntity) and ent.type == "mention":
            # вырезаем кусок текста по оффсету
            mentions.append(text[ent.offset: ent.offset + ent.length])
    if not mentions:
        return None
    username = mentions[-1].lstrip("@").strip()
    return username or None

def extract_target_user(message: Message):
    """
    Порядок:
    1) reply_to_message -> from_user
    2) text_mention (entity.user)
    3) mention @username -> ищем в локальном кэше participants
    """
    if message.reply_to_message and message.reply_to_message.from_user:
        return message.reply_to_message.from_user

    if message.entities:
        for ent in message.entities:
            if isinstance(ent, MessageEntity) and ent.type == "text_mention" and ent.user:
                return ent.user

    uname = extract_mention_username(message)
    if uname:
        found = find_participant_by_username(message.chat.id, uname.lower())
        if found:
            return found
    return None

def clean_reason(args: str | None) -> str:
    if not args:
        return ""
    # Удаляем лишние @username из причины, чтобы не дублить адресата.
    return re.sub(r"@\w+", "", args).strip()

# =========================
# Маршруты
# =========================

router = Router()

@router.message(CommandStart())
async def on_start(message: Message):
    if not is_allowed(message.from_user.id):
        await message.answer("Доступ запрещён.")
        return
    track_message_participants(message)
    await message.answer(
        "Привет! Я бот учёта выговоров.\n"
        "Добавь меня в группу и выдай права администратора.\n"
        "Справка: /help"
    )

@router.message(Command("help"))
async def on_help(message: Message):
    if not is_allowed(message.from_user.id):
        await message.answer("Доступ запрещён.")
        return
    track_message_participants(message)
    await message.answer(
        "<b>Команды:</b>\n"
        "• /warn [причина] @user — выговор адресату (или ответом на сообщение)\n"
        "• /hardwarn [причина] @user — строгий выговор\n"
        "• /warns [@user] — показать выговоры адресата/указанного\n"
        "• /allwarns — сводка по всем в чате\n"
        "• /amnesty (кол-во) [warn|hard|all] @user — амнистия у адресата\n"
        "• /fullamnesty @user — полная амнистия адресату\n\n"
        "<i>Выдавать/снимать выговоры могут только админы чата.</i>",
        parse_mode="HTML",
    )


@router.message(Command("warn"))
async def cmd_warn(message: Message, bot: Bot, command: CommandObject | None = None):
    if not is_allowed(message.from_user.id):
        await message.answer("Доступ запрещён.")
        return
    track_message_participants(message)

    if message.chat.type not in {"group", "supergroup"}:
        await message.answer("Эта команда предназначена для групп/супергрупп.")
        return
    if not await is_admin(bot, message.chat.id, message.from_user.id):
        await message.answer("Только администраторы могут выдавать выговоры.")
        return

    target = extract_target_user(message)
    if not target:
        await message.answer("Кому выговор? Сделайте команду ответом на сообщение или укажите @username.")
        return

    reason = clean_reason(command.args if command else None)

    add_warn(
        chat_id=message.chat.id,
        user_id=target.id,
        user_name=getattr(target, "full_name", None) or "user",
        warn_type="warn",
        reason=reason,
        given_by_id=message.from_user.id,
        given_by_name=message.from_user.full_name,
    )
    await message.answer(
        f"Выговор выдан: {html_user_link(target.id, getattr(target, 'full_name', None) or 'user')}"
        + (f"\nПричина: {reason}" if reason else ""),
        parse_mode="HTML",
    )

@router.message(Command("hardwarn"))
async def cmd_hardwarn(message: Message, bot: Bot, command: CommandObject | None = None):
    if not is_allowed(message.from_user.id):
        await message.answer("Доступ запрещён.")
        return
    track_message_participants(message)

    if message.chat.type not in {"group", "supergroup"}:
        await message.answer("Эта команда предназначена для групп/супергрупп.")
        return
    if not await is_admin(bot, message.chat.id, message.from_user.id):
        await message.answer("Только администраторы могут выдавать строгие выговоры.")
        return

    target = extract_target_user(message)
    if not target:
        await message.answer("Кому строгий выговор? Сделайте команду ответом или укажите @username.")
        return

    reason = clean_reason(command.args if command else None)

    add_warn(
        chat_id=message.chat.id,
        user_id=target.id,
        user_name=getattr(target, "full_name", None) or "user",
        warn_type="hard",
        reason=reason,
        given_by_id=message.from_user.id,
        given_by_name=message.from_user.full_name,
    )
    await message.answer(
        f"Строгий выговор выдан: {html_user_link(target.id, getattr(target, 'full_name', None) or 'user')}"
        + (f"\nПричина: {reason}" if reason else ""),
        parse_mode="HTML",
    )

@router.message(Command("warns"))
async def cmd_warns(message: Message, command: CommandObject | None = None):
    if not is_allowed(message.from_user.id):
        await message.answer("Доступ запрещён.")
        return
    track_message_participants(message)

    target = extract_target_user(message)
    user = target or message.from_user

    rows = get_user_warns(message.chat.id, user.id)
    warn_cnt, hard_cnt = get_user_counts(message.chat.id, user.id)

    if not rows:
        await message.answer(
            f"У {html_user_link(user.id, getattr(user, 'full_name', None) or user.full_name)} нет выговоров.",
            parse_mode="HTML",
        )
        return

    display_name = getattr(user, "full_name", None) or user.full_name
    lines = [
        f"Выговоры для {html_user_link(user.id, display_name)}:",
        f"Обычных: <b>{warn_cnt}</b> | Строгих: <b>{hard_cnt}</b>",
        "— — —",
    ]
    for i, (rec_id, wtype, reason, created_at, giver) in enumerate(rows[:20], start=1):
        tag = "Строгий" if wtype == "hard" else "Обычный"
        who = f" от {giver}" if giver else ""
        why = f" — {reason}" if reason else ""
        when = created_at.split("T")[0]
        lines.append(f"{i}) {tag}{who} ({when}){why}")

    extra = f"\nИ ещё {len(rows) - 20} записей…" if len(rows) > 20 else ""
    await message.answer("\n".join(lines) + extra, parse_mode="HTML")

@router.message(Command("allwarns"))
async def cmd_allwarns(message: Message):
    if not is_allowed(message.from_user.id):
        await message.answer("Доступ запрещён.")
        return
    track_message_participants(message)

    data = get_all_counts(message.chat.id)
    if not data:
        await message.answer("В этом чате нет ни одного выговора.")
        return

    lines = ["<b>Сводка по выговорам в чате:</b>"]
    for user_id, user_name, warn_cnt, hard_cnt in data:
        total = (warn_cnt or 0) + (hard_cnt or 0)
        lines.append(
            f"{html_user_link(user_id, user_name or 'user')} — всего: <b>{total}</b> "
            f"(обычных: {warn_cnt or 0}, строгих: {hard_cnt or 0})"
        )
    await message.answer("\n".join(lines), parse_mode="HTML")

@router.message(Command("amnesty"))
async def cmd_amnesty(message: Message, bot: Bot, command: CommandObject | None = None):
    if not is_allowed(message.from_user.id):
        await message.answer("Доступ запрещён.")
        return
    track_message_participants(message)

    if message.chat.type not in {"group", "supergroup"}:
        await message.answer("Эта команда предназначена для групп/супергрупп.")
        return
    if not await is_admin(bot, message.chat.id, message.from_user.id):
        await message.answer("Только администраторы могут проводить амнистию.")
        return

    target = extract_target_user(message)
    if not target:
        await message.answer("Кому амнистию? Сделайте команду ответом или укажите @username.")
        return

    # ожидается: /amnesty <N> [warn|hard|all] @user
    args = (command.args or "").strip() if command else ""
    count = None
    kind = "all"
    if args:
        parts = re.sub(r"@\w+", "", args).split()
        if parts:
            try:
                count = int(parts[0])
            except Exception:
                count = None
            if len(parts) >= 2 and parts[1].lower() in {"warn", "hard", "all"}:
                kind = parts[1].lower()

    if not count or count <= 0:
        await message.answer("Неверные аргументы.\nПримеры:\n/amnesty 2 @user\n/amnesty 3 warn @user\n/amnesty 1 hard @user")
        return

    amnesty_partial(message.chat.id, target.id, count, kind)
    warn_cnt, hard_cnt = get_user_counts(message.chat.id, target.id)
    await message.answer(
        f"Амнистия применена к {html_user_link(target.id, getattr(target, 'full_name', None) or 'user')}: снято до {count} ({kind}).\n"
        f"Текущий остаток — обычных: <b>{warn_cnt}</b>, строгих: <b>{hard_cnt}</b>.",
        parse_mode="HTML",
    )

@router.message(Command("fullamnesty"))
async def cmd_full_amnesty(message: Message, bot: Bot):
    if not is_allowed(message.from_user.id):
        await message.answer("Доступ запрещён.")
        return
    track_message_participants(message)

    if message.chat.type not in {"group", "supergroup"}:
        await message.answer("Эта команда предназначена для групп/супергрупп.")
        return
    if not await is_admin(bot, message.chat.id, message.from_user.id):
        await message.answer("Только администраторы могут проводить амнистию.")
        return

    target = extract_target_user(message)
    if not target:
        await message.answer("Кому полную амнистию? Сделайте команду ответом или укажите @username.")
        return

    amnesty_full(message.chat.id, target.id)
    await message.answer(
        f"Полная амнистия применена к {html_user_link(target.id, getattr(target, 'full_name', None) or 'user')}.",
        parse_mode="HTML",
    )

# =========================
# Запуск
# =========================

async def set_commands(bot: Bot):
    cmds = [
        BotCommand(command="help", description="Справка"),
        BotCommand(command="warn", description="Выговор (ответ/@user)"),
        BotCommand(command="hardwarn", description="Строгий выговор (ответ/@user)"),
        BotCommand(command="warns", description="Показать выговоры"),
        BotCommand(command="allwarns", description="Сводка по всем выговорам"),
        BotCommand(command="amnesty", description="Амнистия N [warn|hard|all] @user"),
        BotCommand(command="fullamnesty", description="Полная амнистия @user"),
    ]
    await bot.set_my_commands(cmds)

async def main():
    logging.basicConfig(level=logging.INFO)
    load_dotenv()
    token = os.getenv("BOT_TOKEN")
    if not token:
        raise RuntimeError("Укажите BOT_TOKEN в .env")

    db_init()

    bot = Bot(token=token, default=DefaultBotProperties(parse_mode="HTML"))
    dp = Dispatcher()
    dp.include_router(router)
    await set_commands(bot)
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
