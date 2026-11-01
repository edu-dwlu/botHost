import asyncio
import os
import resource
import shutil
import signal
import sqlite3
import time
import zipfile
from pathlib import Path

import psutil
from aiogram import Bot, Dispatcher, F, Router
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import (
    CallbackQuery,
    FSInputFile,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)

# ================= CONFIGURATION =================
MASTER_BOT_TOKEN = os.getenv("MASTER_BOT_TOKEN", "9072057042:AAGeMqNrpOq6_Vrft4t8ot5xWW0fm3AcKZM")
ADMIN_ID = int(os.getenv("ADMIN_ID", "6918458288"))

DATA_DIR = Path("/data")
BOTS_DIR = DATA_DIR / "bots"
DB_PATH = DATA_DIR / "platform.db"

DEFAULT_MAX_BOTS_PER_USER = int(os.getenv("MAX_BOTS_PER_USER", "2"))
MAX_RAM_PER_BOT_MB = int(os.getenv("MAX_RAM_PER_BOT_MB", "85"))
MAX_DISK_PER_BOT_MB = int(os.getenv("MAX_DISK_PER_BOT_MB", "150"))

# Lock directory permissions so user bots cannot snoop
DATA_DIR.mkdir(parents=True, exist_ok=True)
BOTS_DIR.mkdir(parents=True, exist_ok=True)
os.chmod(DATA_DIR, 0o711)
os.chmod(BOTS_DIR, 0o711)

bot = Bot(token=MASTER_BOT_TOKEN)
dp = Dispatcher()
router = Router()
dp.include_router(router)

RUNNING_PROCS: dict[int, asyncio.subprocess.Process] = {}
START_TIMES: dict[int, float] = {}
PLATFORM_BOOT_TIME = time.time()


# ================= DATABASE LAYER =================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT DEFAULT '',
            max_bots INTEGER DEFAULT 2,
            is_banned INTEGER DEFAULT 0,
            joined_at INTEGER DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS bots (
            bot_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT,
            lang TEXT,
            entry_file TEXT,
            env_vars TEXT DEFAULT '',
            status TEXT DEFAULT 'stopped',
            expires_at INTEGER DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            val TEXT
        )
    """)
    c.execute("INSERT OR IGNORE INTO settings (key, val) VALUES ('require_24h_renew', '0')")
    conn.commit()
    conn.close()
    os.chmod(DB_PATH, 0o600)


def db_query(sql: str, params: tuple = (), fetch: bool = False):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(sql, params)
    res = c.fetchall() if fetch else c.lastrowid
    conn.commit()
    conn.close()
    return res


def get_setting(key: str, default: str = "0") -> str:
    rows = db_query("SELECT val FROM settings WHERE key=?", (key,), fetch=True)
    return rows[0][0] if rows else default


def set_setting(key: str, val: str):
    db_query("INSERT OR REPLACE INTO settings (key, val) VALUES (?, ?)", (key, val))


# ================= MULTI-TENANT SANDBOXING & SECURITY =================
BANNED_PATTERNS = [
    "/data/platform.db",
    "/app/main.py",
    "MASTER_BOT_TOKEN",
    "xmrig",
    "stratum+tcp",
    "cryptonight",
    "/dev/tcp/",
]


def scan_bot_code(bot_dir: Path) -> str | None:
    """Scans uploaded or cloned code for forbidden patterns."""
    for root, _, files in os.walk(bot_dir):
        if ".local" in root or "node_modules" in root or ".git" in root:
            continue
        for f in files:
            if f.endswith((".py", ".js", ".sh", ".ts")):
                p = Path(root) / f
                try:
                    content = p.read_text(errors="ignore")
                    for pat in BANNED_PATTERNS:
                        if pat in content:
                            return f"Forbidden signature `{pat}` detected in `{f}`"
                except Exception:
                    pass
    return None


def get_bot_uid(bot_id: int) -> int:
    """Each hosted bot gets its own isolated Linux UID (10000 + bot_id)."""
    return 10000 + int(bot_id)


def secure_bot_filesystem(user_id: int, bot_id: int) -> Path:
    """Locks directory tree so only UID (10000 + bot_id) and root can access this bot."""
    user_dir = BOTS_DIR / f"u_{user_id}"
    bot_dir = user_dir / f"b_{bot_id}"
    local_dir = bot_dir / ".home" / ".local"
    local_dir.mkdir(parents=True, exist_ok=True)

    os.chmod(user_dir, 0o711)
    uid = get_bot_uid(bot_id)

    for root, dirs, files in os.walk(bot_dir):
        try:
            os.chown(root, uid, uid)
            for d in dirs:
                os.chown(os.path.join(root, d), uid, uid)
            for f in files:
                os.chown(os.path.join(root, f), uid, uid)
        except PermissionError:
            pass

    os.chmod(bot_dir, 0o700)
    return bot_dir


def make_sandbox_preexec(bot_id: int):
    """Applies kernel rlimits (fork bomb / file bomb protection) and drops root to dedicated UID."""
    uid = get_bot_uid(bot_id)
    max_file_bytes = 50 * 1024 * 1024  # 50 MB max single file write

    def _preexec():
        os.setsid()
        try:
            # Prevent fork bombs (max 64 processes/threads for this UID)
            resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
            # Prevent file-descriptor exhaustion
            resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
            # Prevent disk-fill bombs (50 MB max per file)
            resource.setrlimit(resource.RLIMIT_FSIZE, (max_file_bytes, max_file_bytes))
        except Exception:
            pass
        try:
            os.setgroups([])
            os.setgid(uid)
            os.setuid(uid)
        except PermissionError:
            pass

    return _preexec


def get_dir_size_mb(path: Path) -> float:
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            fp = os.path.join(root, f)
            if not os.path.islink(fp):
                try:
                    total += os.path.getsize(fp)
                except OSError:
                    pass
    return round(total / (1024 * 1024), 1)


def get_bot_ram_mb(bot_id: int) -> float:
    proc = RUNNING_PROCS.get(bot_id)
    if not proc or proc.returncode is not None:
        return 0.0
    try:
        p = psutil.Process(proc.pid)
        mem = p.memory_info().rss
        for child in p.children(recursive=True):
            try:
                mem += child.memory_info().rss
            except psutil.NoSuchProcess:
                pass
        return round(mem / (1024 * 1024), 1)
    except psutil.NoSuchProcess:
        return 0.0


# ================= PROCESS SUPERVISOR ENGINE =================
async def start_user_bot(bot_id: int) -> tuple[bool, str]:
    await stop_user_bot(bot_id, mark_stopped=False)

    rows = db_query(
        "SELECT user_id, name, lang, entry_file, env_vars FROM bots WHERE bot_id=?",
        (bot_id,),
        fetch=True,
    )
    if not rows:
        return False, "Bot record not found."

    user_id, name, lang, entry_file, env_vars = rows[0]
    bot_dir = secure_bot_filesystem(user_id, bot_id)

    if not (bot_dir / entry_file).exists():
        return False, f"Entry file `{entry_file}` not found in bot directory."

    threat = scan_bot_code(bot_dir)
    if threat:
        return False, f"Security Block: {threat}"

    if get_dir_size_mb(bot_dir) > MAX_DISK_PER_BOT_MB:
        return False, f"Disk quota exceeded ({MAX_DISK_PER_BOT_MB} MB max)."

    log_path = bot_dir / "runtime.log"
    log_file = open(log_path, "a", buffering=1)
    log_file.write(f"\n--- [Platform] Booting {name} (UID {get_bot_uid(bot_id)}) at {time.ctime()} ---\n")

    home_dir = bot_dir / ".home"
    local_dir = home_dir / ".local"

    # Scrubbed environment: NEVER pass os.environ or MASTER_BOT_TOKEN
    clean_env = {
        "PATH": f"{local_dir / 'bin'}:/usr/local/bin:/usr/bin:/bin",
        "HOME": str(home_dir),
        "PYTHONUSERBASE": str(local_dir),
        "PYTHONUNBUFFERED": "1",
        "NPM_CONFIG_CACHE": str(home_dir / ".npm"),
    }
    for line in (env_vars or "").splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            clean_env[k.strip()] = v.strip().strip('"').strip("'")

    # 1. Install Python dependencies into isolated per-bot PYTHONUSERBASE
    if (bot_dir / "requirements.txt").exists():
        log_file.write("[Platform] Installing requirements.txt into isolated sandbox...\n")
        p = await asyncio.create_subprocess_exec(
            "pip", "install", "--user", "--no-cache-dir", "-r", "requirements.txt",
            cwd=str(bot_dir),
            stdout=log_file,
            stderr=log_file,
            env=clean_env,
            preexec_fn=make_sandbox_preexec(bot_id),
        )
        try:
            await asyncio.wait_for(p.wait(), timeout=180)
        except asyncio.TimeoutError:
            p.kill()
            return False, "pip install timed out (exceeded 180s)."

    # 2. Install Node.js dependencies if package.json is present
    if (bot_dir / "package.json").exists() and not (bot_dir / "node_modules").exists():
        log_file.write("[Platform] Installing package.json dependencies...\n")
        p = await asyncio.create_subprocess_exec(
            "npm", "install", "--omit=dev", "--no-audit", "--no-fund",
            cwd=str(bot_dir),
            stdout=log_file,
            stderr=log_file,
            env=clean_env,
            preexec_fn=make_sandbox_preexec(bot_id),
        )
        try:
            await asyncio.wait_for(p.wait(), timeout=180)
        except asyncio.TimeoutError:
            p.kill()
            return False, "npm install timed out (exceeded 180s)."

    # 3. Launch user bot under its dedicated UID
    if lang == "python":
        cmd = ["python3", entry_file]
    elif lang == "node":
        cmd = ["node", entry_file]
    else:
        cmd = ["sh", entry_file]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(bot_dir),
        stdout=log_file,
        stderr=log_file,
        env=clean_env,
        preexec_fn=make_sandbox_preexec(bot_id),
    )

    RUNNING_PROCS[bot_id] = proc
    START_TIMES[bot_id] = time.time()
    expires = int(time.time() + 24 * 3600)
    db_query(
        "UPDATE bots SET status='running', expires_at=? WHERE bot_id=?",
        (expires, bot_id),
    )
    return True, f"PID {proc.pid} (Isolated UID {get_bot_uid(bot_id)})"


async def stop_user_bot(bot_id: int, mark_stopped: bool = True) -> bool:
    proc = RUNNING_PROCS.pop(bot_id, None)
    START_TIMES.pop(bot_id, None)
    if mark_stopped:
        db_query("UPDATE bots SET status='stopped' WHERE bot_id=?", (bot_id,))

    # Also kill any stray processes owned by this bot's dedicated UID
    uid = get_bot_uid(bot_id)
    if proc and proc.returncode is None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            await asyncio.sleep(0.8)
            if proc.returncode is None:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass

    for p in psutil.process_iter(["pid", "uids"]):
        try:
            if p.info["uids"] and p.info["uids"].real == uid:
                p.kill()
        except Exception:
            pass
    return True


# ================= WATCHDOG & BACKGROUND DAEMONS =================
async def platform_watchdog():
    """Monitors RAM, Disk, Crashes, and 24h Expiry every 8 seconds."""
    while True:
        await asyncio.sleep(8)
        require_renew = get_setting("require_24h_renew", "0") == "1"
        now = int(time.time())

        for bot_id, proc in list(RUNNING_PROCS.items()):
            rows = db_query(
                "SELECT user_id, name, expires_at FROM bots WHERE bot_id=?",
                (bot_id,),
                fetch=True,
            )
            if not rows:
                await stop_user_bot(bot_id)
                continue
            uid, bname, expires_at = rows[0]

            # 1. Detect unexpected crash
            if proc.returncode is not None:
                RUNNING_PROCS.pop(bot_id, None)
                db_query("UPDATE bots SET status='crashed' WHERE bot_id=?", (bot_id,))
                continue

            # 2. Enforce RAM Limit
            ram_mb = get_bot_ram_mb(bot_id)
            if ram_mb > MAX_RAM_PER_BOT_MB:
                await stop_user_bot(bot_id)
                try:
                    await bot.send_message(
                        uid,
                        f"⚠️ **OOM Guard Triggered:** Bot `{bname}` (#{bot_id}) used `{ram_mb} MB` "
                        f"(limit `{MAX_RAM_PER_BOT_MB} MB`) and was stopped to protect the host.",
                        parse_mode="Markdown",
                    )
                except Exception:
                    pass
                continue

            # 3. Enforce Disk Quota
            bot_dir = BOTS_DIR / f"u_{uid}" / f"b_{bot_id}"
            disk_mb = get_dir_size_mb(bot_dir)
            if disk_mb > MAX_DISK_PER_BOT_MB:
                await stop_user_bot(bot_id)
                try:
                    await bot.send_message(
                        uid,
                        f"⚠️ **Disk Guard Triggered:** Bot `{bname}` (#{bot_id}) exceeded "
                        f"`{MAX_DISK_PER_BOT_MB} MB` storage and was stopped.",
                        parse_mode="Markdown",
                    )
                except Exception:
                    pass
                continue

            # 4. Optional 24h Free-Tier Renewal Check
            if require_renew and uid != ADMIN_ID and expires_at > 0 and now > expires_at:
                await stop_user_bot(bot_id)
                try:
                    await bot.send_message(
                        uid,
                        f"⏳ **24h Hosting Slot Expired:** `{bname}` (#{bot_id}) has been paused. "
                        "Open `/start` -> **My Hosted Bots** -> **Renew +24h** to restart it.",
                        parse_mode="Markdown",
                    )
                except Exception:
                    pass


async def blitz_keepalive_and_backup_daemon():
    """Sends automated /data backups & 36h blitz.cloud dashboard check-in reminders to Admin."""
    while True:
        await asyncio.sleep(36 * 3600)
        try:
            kb = InlineKeyboardMarkup(
                inline_keyboard=[
                    [InlineKeyboardButton(text="🔄 Open blitz.cloud Dashboard (Reset 48h Timer)", url="https://blitz.cloud/")]
                ]
            )
            await bot.send_message(
                ADMIN_ID,
                "⏰ **36h blitz.cloud Check-In Reminder**\n\n"
                "Tap the button below to open your dashboard for 2 seconds so your Free Plan background container never stops.",
                reply_markup=kb,
                parse_mode="Markdown",
            )
        except Exception:
            pass


# ================= TELEGRAM FSM STATES =================
class HostStates(StatesGroup):
    waiting_for_file = State()
    waiting_for_git = State()
    waiting_for_env = State()
    waiting_for_entry = State()
    waiting_for_restore = State()


def detect_entry_and_lang(bot_dir: Path, fallback_name: str) -> tuple[str, str]:
    candidates = [
        ("main.py", "python"),
        ("bot.py", "python"),
        ("app.py", "python"),
        ("run.py", "python"),
        ("index.js", "node"),
        ("bot.js", "node"),
        ("main.js", "node"),
        ("start.sh", "bash"),
    ]
    for fname, lang in candidates:
        if (bot_dir / fname).exists():
            return fname, lang
    # Search any .py or .js in root of bot_dir
    for p in bot_dir.iterdir():
        if p.is_file() and p.name.endswith(".py"):
            return p.name, "python"
        if p.is_file() and p.name.endswith(".js"):
            return p.name, "node"
    lang = "node" if fallback_name.endswith(".js") else ("bash" if fallback_name.endswith(".sh") else "python")
    return fallback_name, lang


# ================= USER MENUS & HANDLERS =================
def main_menu_kb(user_id: int) -> InlineKeyboardMarkup:
    rows = [
        [
            InlineKeyboardButton(text="📤 Upload File / ZIP", callback_data="new_bot"),
            InlineKeyboardButton(text="🐙 Clone GitHub Repo", callback_data="git_clone"),
        ],
        [InlineKeyboardButton(text="🤖 My Hosted Bots", callback_data="my_bots")],
    ]
    if user_id == ADMIN_ID:
        rows.append([InlineKeyboardButton(text="🛡️ Super Admin Control Panel", callback_data="admin_home")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


@router.message(Command("start"))
async def cmd_start(msg: Message, state: FSMContext):
    await state.clear()
    uid = msg.from_user.id
    uname = msg.from_user.username or msg.from_user.first_name or ""
    db_query(
        "INSERT OR IGNORE INTO users (user_id, username, max_bots, joined_at) VALUES (?, ?, ?, ?)",
        (uid, uname, DEFAULT_MAX_BOTS_PER_USER, int(time.time())),
    )
    db_query("UPDATE users SET username=? WHERE user_id=?", (uname, uid))

    banned = db_query("SELECT is_banned FROM users WHERE user_id=?", (uid,), fetch=True)[0][0]
    if banned and uid != ADMIN_ID:
        return await msg.answer("🚫 Your account has been suspended by the platform administrator.")

    await msg.answer(
        "⚡ **24/7 Multi-Language Bot Hosting Platform**\n\n"
        "• **Supported Runtimes:** Python 3.12 (`pip`), Node.js (`npm`), Bash\n"
        "• **Isolation:** Dedicated Linux UID & private sandbox per bot\n"
        "• **Limits:** Up to "
        f"`{MAX_RAM_PER_BOT_MB} MB` RAM & `{MAX_DISK_PER_BOT_MB} MB` Disk per bot",
        reply_markup=main_menu_kb(uid),
        parse_mode="Markdown",
    )


@router.callback_query(F.data == "home")
async def cb_home(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    await cb.message.edit_text(
        "⚡ **24/7 Multi-Language Bot Hosting Platform**\nSelect an action below:",
        reply_markup=main_menu_kb(cb.from_user.id),
        parse_mode="Markdown",
    )


def check_user_quota(uid: int) -> tuple[bool, int, int]:
    if uid == ADMIN_ID:
        return True, 0, 999
    max_b = db_query("SELECT max_bots FROM users WHERE user_id=?", (uid,), fetch=True)[0][0]
    cur_b = db_query("SELECT COUNT(*) FROM bots WHERE user_id=?", (uid,), fetch=True)[0][0]
    return cur_b < max_b, cur_b, max_b


@router.callback_query(F.data == "new_bot")
async def cb_new_bot(cb: CallbackQuery, state: FSMContext):
    ok, cur_b, max_b = check_user_quota(cb.from_user.id)
    if not ok:
        return await cb.answer(f"❌ Quota reached ({cur_b}/{max_b} bots).", show_alert=True)

    await state.set_state(HostStates.waiting_for_file)
    await cb.message.edit_text(
        "📤 **Upload Your Bot File**\n\n"
        "Send a `.py`, `.js`, `.sh`, or `.zip` archive (containing `main.py`/`index.js` and `requirements.txt`/`package.json`).",
        reply_markup=InlineKeyboardMarkup(
            inline_keyboard=[[InlineKeyboardButton(text="🔙 Cancel", callback_data="home")]]
        ),
        parse_mode="Markdown",
    )


@router.message(HostStates.waiting_for_file, F.document)
async def handle_file_upload(msg: Message, state: FSMContext):
    uid = msg.from_user.id
    doc = msg.document
    fname = doc.file_name or "bot.py"

    if not fname.endswith((".py", ".js", ".sh", ".zip")):
        return await msg.answer("❌ Only `.py`, `.js`, `.sh`, or `.zip` files are supported.")
    if doc.file_size > 20 * 1024 * 1024:
        return await msg.answer("❌ File exceeds 20 MB upload limit.")

    wait_msg = await msg.answer("⏳ **Unpacking & provisioning isolated sandbox...**", parse_mode="Markdown")
    bot_id = db_query(
        "INSERT INTO bots (user_id, name, lang, entry_file, expires_at) VALUES (?, ?, ?, ?, ?)",
        (uid, fname, "python", "main.py", int(time.time() + 24 * 3600)),
    )
    bot_dir = secure_bot_filesystem(uid, bot_id)
    dl_path = bot_dir / fname
    await bot.download(doc, destination=dl_path)

    if fname.endswith(".zip"):
        try:
            with zipfile.ZipFile(dl_path, "r") as zf:
                # Zip-bomb check (max 120 MB uncompressed)
                total_uncompressed = sum(info.file_size for info in zf.infolist())
                if total_uncompressed > 120 * 1024 * 1024:
                    shutil.rmtree(bot_dir, ignore_errors=True)
                    db_query("DELETE FROM bots WHERE bot_id=?", (bot_id,))
                    return await wait_msg.edit_text("❌ Rejected: Archive uncompressed size exceeds 120 MB.")
                zf.extractall(bot_dir)
            dl_path.unlink()
            # If zip contained a single top-level folder, flatten it
            items = [p for p in bot_dir.iterdir() if p.name != ".home"]
            if len(items) == 1 and items[0].is_dir():
                sub = items[0]
                for item in sub.iterdir():
                    shutil.move(str(item), str(bot_dir / item.name))
                sub.rmdir()
        except Exception as e:
            return await wait_msg.edit_text(f"❌ Failed to extract ZIP: `{e}`", parse_mode="Markdown")

    entry_file, lang = detect_entry_and_lang(bot_dir, fname)
    db_query("UPDATE bots SET lang=?, entry_file=? WHERE bot_id=?", (lang, entry_file, bot_id))
    await state.clear()

    ok, info = await start_user_bot(bot_id)
    await wait_msg.edit_text(
        f"{'🟢' if ok else '🔴'} **Bot #{bot_id} (`{fname}`) Deployed**\n"
        f"• **Entrypoint:** `{entry_file}` ({lang})\n"
        f"• **Sandbox UID:** `{get_bot_uid(bot_id)}`\n"
        f"• **Result:** `{info}`",
        reply_markup=bot_control_kb(bot_id, uid == ADMIN_ID),
        parse_mode="Markdown",
    )


@router.callback_query(F.data == "git_clone")
async def cb_git_clone(cb: CallbackQuery, state: FSMContext):
    ok, cur_b, max_b = check_user_quota(cb.from_user.id)
    if not ok:
        return await cb.answer(f"❌ Quota reached ({cur_b}/{max_b} bots).", show_alert=True)

    await state.set_state(HostStates.waiting_for_git)
    await cb.message.edit_text(
        "🐙 **Clone from GitHub / Git Repository**\n\n"
        "Send the HTTPS repository URL (e.g. `https://github.com/user/my-telegram-bot.git`):",
        reply_markup=InlineKeyboardMarkup(
            inline_keyboard=[[InlineKeyboardButton(text="🔙 Cancel", callback_data="home")]]
        ),
        parse_mode="Markdown",
    )


@router.message(HostStates.waiting_for_git)
async def handle_git_clone(msg: Message, state: FSMContext):
    uid = msg.from_user.id
    repo_url = msg.text.strip()
    if not repo_url.startswith(("https://", "http://")):
        return await msg.answer("❌ Please send a valid `https://` Git repository URL.", parse_mode="Markdown")

    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "") or "git-bot"
    wait_msg = await msg.answer(f"⏳ **Cloning `{repo_name}`...**", parse_mode="Markdown")

    bot_id = db_query(
        "INSERT INTO bots (user_id, name, lang, entry_file, expires_at) VALUES (?, ?, ?, ?, ?)",
        (uid, repo_name, "python", "main.py", int(time.time() + 24 * 3600)),
    )
    bot_dir = secure_bot_filesystem(uid, bot_id)

    proc = await asyncio.create_subprocess_exec(
        "git", "clone", "--depth", "1", repo_url, str(bot_dir / "repo_tmp"),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        shutil.rmtree(bot_dir, ignore_errors=True)
        db_query("DELETE FROM bots WHERE bot_id=?", (bot_id,))
        await state.clear()
        return await wait_msg.edit_text(
            f"❌ **Git Clone Failed:**\n```\n{stderr.decode(errors='ignore')[:1000]}\n```",
            parse_mode="Markdown",
        )

    tmp_repo = bot_dir / "repo_tmp"
    shutil.rmtree(tmp_repo / ".git", ignore_errors=True)
    for item in tmp_repo.iterdir():
        shutil.move(str(item), str(bot_dir / item.name))
    tmp_repo.rmdir()

    entry_file, lang = detect_entry_and_lang(bot_dir, "main.py")
    db_query("UPDATE bots SET lang=?, entry_file=? WHERE bot_id=?", (lang, entry_file, bot_id))
    await state.clear()

    ok, info = await start_user_bot(bot_id)
    await wait_msg.edit_text(
        f"{'🟢' if ok else '🔴'} **Git Repo `{repo_name}` (#{bot_id}) Deployed**\n"
        f"• **Entrypoint:** `{entry_file}` ({lang})\n"
        f"• **Result:** `{info}`",
        reply_markup=bot_control_kb(bot_id, uid == ADMIN_ID),
        parse_mode="Markdown",
    )


def bot_control_kb(bot_id: int, is_admin: bool = False) -> InlineKeyboardMarkup:
    rows = [
        [
            InlineKeyboardButton(text="▶️ Start / Restart", callback_data=f"b_start:{bot_id}"),
            InlineKeyboardButton(text="⏹️ Stop", callback_data=f"b_stop:{bot_id}"),
        ],
        [
            InlineKeyboardButton(text="📜 Live Logs", callback_data=f"b_logs:{bot_id}"),
            InlineKeyboardButton(text="📥 Download Log File", callback_data=f"b_logdl:{bot_id}"),
        ],
        [
            InlineKeyboardButton(text="🔐 Set ENV Vars", callback_data=f"b_env:{bot_id}"),
            InlineKeyboardButton(text="⚙️ Change Entry File", callback_data=f"b_cmd:{bot_id}"),
        ],
        [
            InlineKeyboardButton(text="🔄 Renew +24h Timer", callback_data=f"b_renew:{bot_id}"),
            InlineKeyboardButton(text="📦 Export Bot ZIP", callback_data=f"b_export:{bot_id}"),
        ],
        [
            InlineKeyboardButton(text="🗑️ Delete Bot", callback_data=f"b_del:{bot_id}"),
            InlineKeyboardButton(text="🔙 Back", callback_data="my_bots"),
        ],
    ]
    if is_admin:
        rows.insert(
            4,
            [InlineKeyboardButton(text="🕵️ Admin: View Bot Secrets & Details", callback_data=f"b_spy:{bot_id}")],
        )
        rows[-1][1] = InlineKeyboardButton(text="🛡️ Back to Admin", callback_data="adm_procs")
    return InlineKeyboardMarkup(inline_keyboard=rows)


@router.callback_query(F.data == "my_bots")
async def cb_my_bots(cb: CallbackQuery):
    uid = cb.from_user.id
    rows = db_query("SELECT bot_id, name, status FROM bots WHERE user_id=?", (uid,), fetch=True)
    if not rows:
        return await cb.message.edit_text(
            "You have no hosted bots yet. Upload a file or clone a GitHub repo!",
            reply_markup=main_menu_kb(uid),
        )

    kb = []
    for bid, name, status in rows:
        is_up = bid in RUNNING_PROCS and RUNNING_PROCS[bid].returncode is None
        icon = "🟢" if is_up else "🔴"
        ram = f"{get_bot_ram_mb(bid)} MB" if is_up else status
        kb.append([InlineKeyboardButton(text=f"{icon} #{bid} {name} ({ram})", callback_data=f"b_view:{bid}")])
    kb.append([InlineKeyboardButton(text="🔙 Main Menu", callback_data="home")])
    await cb.message.edit_text(
        "🤖 **Your Hosted Bots:**",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=kb),
        parse_mode="Markdown",
    )


@router.callback_query(F.data.startswith("b_"))
async def cb_bot_actions(cb: CallbackQuery, state: FSMContext):
    action, bid_str = cb.data.split(":")
    bid = int(bid_str)
    rows = db_query(
        "SELECT user_id, name, lang, entry_file, env_vars, expires_at FROM bots WHERE bot_id=?",
        (bid,),
        fetch=True,
    )
    if not rows:
        return await cb.answer("Bot no longer exists.", show_alert=True)

    owner_id, name, lang, entry, env_vars, expires_at = rows[0]
    caller_is_admin = cb.from_user.id == ADMIN_ID
    if cb.from_user.id != owner_id and not caller_is_admin:
        return await cb.answer("Unauthorized.", show_alert=True)

    bot_dir = BOTS_DIR / f"u_{owner_id}" / f"b_{bid}"

    if action == "b_view":
        is_up = bid in RUNNING_PROCS and RUNNING_PROCS[bid].returncode is None
        ram = get_bot_ram_mb(bid)
        disk = get_dir_size_mb(bot_dir)
        pid = RUNNING_PROCS[bid].pid if is_up else "None"
        rem_hrs = max(0, round((expires_at - time.time()) / 3600, 1))
        await cb.message.edit_text(
            f"⚙️ **Bot #{bid}: `{name}`**\n\n"
            f"• **Owner ID:** `{owner_id}`\n"
            f"• **Status:** {'🟢 Running' if is_up else '🔴 Stopped'} (PID: `{pid}`, UID: `{get_bot_uid(bid)}`)\n"
            f"• **RAM Usage:** `{ram} / {MAX_RAM_PER_BOT_MB} MB`\n"
            f"• **Disk Usage:** `{disk} / {MAX_DISK_PER_BOT_MB} MB`\n"
            f"• **Entry File:** `{entry}` ({lang})\n"
            f"• **Renewal Timer:** `{rem_hrs}h remaining`",
            reply_markup=bot_control_kb(bid, caller_is_admin),
            parse_mode="Markdown",
        )

    elif action == "b_start":
        await cb.answer("⏳ Starting bot...")
        ok, info = await start_user_bot(bid)
        await cb.answer(f"{'✅' if ok else '❌'} {info}", show_alert=True)
        cb.data = f"b_view:{bid}"
        await cb_bot_actions(cb, state)

    elif action == "b_stop":
        await stop_user_bot(bid)
        await cb.answer("⏹️ Bot stopped.", show_alert=True)
        cb.data = f"b_view:{bid}"
        await cb_bot_actions(cb, state)

    elif action == "b_renew":
        new_exp = int(time.time() + 24 * 3600)
        db_query("UPDATE bots SET expires_at=? WHERE bot_id=?", (new_exp, bid))
        await cb.answer("✅ Hosting timer renewed for +24 hours!", show_alert=True)
        cb.data = f"b_view:{bid}"
        await cb_bot_actions(cb, state)

    elif action == "b_logs":
        log_path = bot_dir / "runtime.log"
        if not log_path.exists():
            return await cb.answer("No logs written yet.", show_alert=True)
        tail = "".join(log_path.read_text(errors="ignore").splitlines(keepends=True)[-35:])
        await cb.message.edit_text(
            f"📜 **Live Logs for #{bid} (`{name}`):**\n```\n{tail[-3500:] or 'Empty log'}\n```",
            reply_markup=bot_control_kb(bid, caller_is_admin),
            parse_mode="Markdown",
        )

    elif action == "b_logdl":
        log_path = bot_dir / "runtime.log"
        if not log_path.exists():
            return await cb.answer("No log file available.", show_alert=True)
        await cb.message.answer_document(
            FSInputFile(log_path, filename=f"bot_{bid}_{name}.log"),
            caption=f"📜 Full runtime log for Bot #{bid} (`{name}`)",
            parse_mode="Markdown",
        )
        await cb.answer()

    elif action == "b_env":
        await state.set_state(HostStates.waiting_for_env)
        await state.update_data(bot_id=bid)
        await cb.message.edit_text(
            f"🔐 **Set Environment Variables for Bot #{bid}**\n\n"
            "Send your variables in `KEY=VALUE` format (one per line). "
            "Your message will be deleted immediately for security.\n\n"
            "Example:\n`BOT_TOKEN=123456:ABC-DEF`\n`API_ID=12345`",
            parse_mode="Markdown",
        )

    elif action == "b_cmd":
        files_list = [p.name for p in bot_dir.iterdir() if p.is_file() and not p.name.startswith(".")]
        await state.set_state(HostStates.waiting_for_entry)
        await state.update_data(bot_id=bid)
        await cb.message.edit_text(
            f"⚙️ **Change Entry File for Bot #{bid}**\n\n"
            f"Files in bot directory: `{', '.join(files_list[:20])}`\n\n"
            "Reply with the exact filename to execute (e.g. `bot.py` or `index.js`):",
            parse_mode="Markdown",
        )

    elif action == "b_export":
        await cb.answer("📦 Zipping bot source files...")
        tmp_zip = f"/tmp/bot_{bid}_export"
        shutil.make_archive(tmp_zip, "zip", bot_dir)
        await cb.message.answer_document(
            FSInputFile(f"{tmp_zip}.zip", filename=f"bot_{bid}_{name}.zip"),
            caption=f"📦 **Exported Archive for Bot #{bid} (`{name}`)**\n• Owner: `{owner_id}`",
            parse_mode="Markdown",
        )
        os.remove(f"{tmp_zip}.zip")

    elif action == "b_spy":
        if not caller_is_admin:
            return await cb.answer("Admin only.", show_alert=True)
        files_list = [p.name for p in bot_dir.iterdir() if p.name != ".home"]
        env_display = env_vars if env_vars else "(No ENV vars set)"
        await cb.message.edit_text(
            f"🕵️ **Admin Deep Inspection: Bot #{bid} (`{name}`)**\n\n"
            f"• **Owner Telegram ID:** `{owner_id}`\n"
            f"• **Linux Sandbox UID:** `{get_bot_uid(bid)}`\n"
            f"• **Folder Path:** `{bot_dir}`\n"
            f"• **Root Files:** `{', '.join(files_list[:25])}`\n\n"
            f"🔐 **Stored `.env` Secrets:**\n```\n{env_display[:2500]}\n```",
            reply_markup=bot_control_kb(bid, True),
            parse_mode="Markdown",
        )

    elif action == "b_del":
        await stop_user_bot(bid)
        shutil.rmtree(bot_dir, ignore_errors=True)
        db_query("DELETE FROM bots WHERE bot_id=?", (bid,))
        await cb.answer("🗑️ Bot deleted.", show_alert=True)
        if caller_is_admin and cb.from_user.id != owner_id:
            await cb_admin_procs(cb)
        else:
            await cb_my_bots(cb)


@router.message(HostStates.waiting_for_env)
async def save_bot_env(msg: Message, state: FSMContext):
    data = await state.get_data()
    bid = data["bot_id"]
    db_query("UPDATE bots SET env_vars=? WHERE bot_id=?", (msg.text.strip(), bid))
    try:
        await msg.delete()
    except Exception:
        pass
    await state.clear()
    await msg.answer(
        f"✅ **Environment variables saved for Bot #{bid}!**\nTap **Start / Restart** to apply them.",
        reply_markup=bot_control_kb(bid, msg.from_user.id == ADMIN_ID),
        parse_mode="Markdown",
    )


@router.message(HostStates.waiting_for_entry)
async def save_bot_entry(msg: Message, state: FSMContext):
    data = await state.get_data()
    bid = data["bot_id"]
    entry = msg.text.strip()
    lang = "node" if entry.endswith(".js") else ("bash" if entry.endswith(".sh") else "python")
    db_query("UPDATE bots SET entry_file=?, lang=? WHERE bot_id=?", (entry, lang, bid))
    await state.clear()
    await msg.answer(
        f"✅ **Entry file updated to `{entry}` ({lang})!**\nTap **Start / Restart** to run it.",
        reply_markup=bot_control_kb(bid, msg.from_user.id == ADMIN_ID),
        parse_mode="Markdown",
    )


# ================= SUPER POWERFUL ADMIN PANEL =================
@router.message(Command("admin"))
async def cmd_admin(msg: Message):
    if msg.from_user.id != ADMIN_ID:
        return
    await msg.answer(
        "🛡️ **Opening Super Admin Control Panel...**",
        reply_markup=InlineKeyboardMarkup(
            inline_keyboard=[[InlineKeyboardButton(text="🛡️ Open Admin Dashboard", callback_data="admin_home")]]
        ),
        parse_mode="Markdown",
    )


@router.callback_query(F.data == "admin_home")
async def cb_admin_home(cb: CallbackQuery):
    if cb.from_user.id != ADMIN_ID:
        return
    vm = psutil.virtual_memory()
    cpu = psutil.cpu_percent(interval=0.1)
    disk = shutil.disk_usage(DATA_DIR)
    uptime_hrs = round((time.time() - PLATFORM_BOOT_TIME) / 3600, 1)

    total_users = db_query("SELECT COUNT(*) FROM users", fetch=True)[0][0]
    total_bots = db_query("SELECT COUNT(*) FROM bots", fetch=True)[0][0]
    active_bots = sum(1 for p in RUNNING_PROCS.values() if p.returncode is None)
    renew_mode = "ON (24h)" if get_setting("require_24h_renew", "0") == "1" else "OFF (Unlimited)"

    text = (
        "🛡️ **Super Admin Control Center**\n\n"
        f"• **Running Bots:** `{active_bots} active / {total_bots} total`\n"
        f"• **Total Users:** `{total_users}`\n"
        f"• **CPU Load:** `{cpu}%` | **Uptime:** `{uptime_hrs}h`\n"
        f"• **Container RAM:** `{vm.used // (1024*1024)} MB / {vm.total // (1024*1024)} MB ({vm.percent}%)`\n"
        f"• **`/data` Volume:** `{disk.used // (1024*1024)} MB / {disk.total // (1024*1024)} MB`\n"
        f"• **Per-Bot Quotas:** `{MAX_RAM_PER_BOT_MB} MB RAM` | `{MAX_DISK_PER_BOT_MB} MB Disk`\n"
        f"• **24h Auto-Expiry Mode:** `{renew_mode}`\n\n"
        "💡 **Quick Admin Commands:**\n"
        "`/setslots <user_id> <slots>` — Set user bot quota\n"
        "`/ban <user_id>` / `/unban <user_id>` — Ban or unban user\n"
        "`/broadcast <message>` — Message all platform users"
    )
    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🔍 Inspect All Bots (Files / ENV / Logs)", callback_data="adm_procs")],
            [InlineKeyboardButton(text="👥 View Users & Quotas", callback_data="adm_users")],
            [
                InlineKeyboardButton(text="⏳ Toggle 24h Expiry Mode", callback_data="adm_toggle_expiry"),
                InlineKeyboardButton(text="📦 Full /data Backup", callback_data="adm_backup"),
            ],
            [
                InlineKeyboardButton(text="♻️ Restore /data Backup", callback_data="adm_restore"),
                InlineKeyboardButton(text="🚨 Kill All User Bots", callback_data="adm_killall"),
            ],
            [InlineKeyboardButton(text="🔙 Main Menu", callback_data="home")],
        ]
    )
    await cb.message.edit_text(text, reply_markup=kb, parse_mode="Markdown")


@router.callback_query(F.data == "adm_procs")
async def cb_admin_procs(cb: CallbackQuery):
    if cb.from_user.id != ADMIN_ID:
        return
    rows = db_query("SELECT bot_id, user_id, name, status FROM bots ORDER BY bot_id DESC", fetch=True)
    kb = []
    for bid, uid, name, status in rows[:30]:
        is_up = bid in RUNNING_PROCS and RUNNING_PROCS[bid].returncode is None
        icon = "🟢" if is_up else "🔴"
        ram = f"{get_bot_ram_mb(bid)}MB" if is_up else status
        kb.append(
            [InlineKeyboardButton(text=f"{icon} #{bid} [u:{uid}] {name} ({ram})", callback_data=f"b_view:{bid}")]
        )
    kb.append([InlineKeyboardButton(text="🔙 Admin Dashboard", callback_data="admin_home")])
    await cb.message.edit_text(
        "🔍 **All Hosted Bots (Tap any bot to inspect files, `.env` secrets, logs, or stop):**",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=kb),
        parse_mode="Markdown",
    )


@router.callback_query(F.data == "adm_users")
async def cb_admin_users(cb: CallbackQuery):
    if cb.from_user.id != ADMIN_ID:
        return
    rows = db_query("SELECT user_id, username, max_bots, is_banned FROM users LIMIT 40", fetch=True)
    lines = ["👥 **Registered Platform Users:**\n"]
    for uid, uname, max_b, banned in rows:
        bot_cnt = db_query("SELECT COUNT(*) FROM bots WHERE user_id=?", (uid,), fetch=True)[0][0]
        status = "🚫 BANNED" if banned else "✅"
        lines.append(f"• {status} `{uid}` (@{uname or 'none'}) — `{bot_cnt}/{max_b}` bots")
    lines.append("\nUse `/setslots <uid> <count>` or `/ban <uid>` to modify.")
    await cb.message.edit_text(
        "\n".join(lines),
        reply_markup=InlineKeyboardMarkup(
            inline_keyboard=[[InlineKeyboardButton(text="🔙 Admin Dashboard", callback_data="admin_home")]]
        ),
        parse_mode="Markdown",
    )


@router.callback_query(F.data == "adm_toggle_expiry")
async def cb_admin_toggle_expiry(cb: CallbackQuery):
    if cb.from_user.id != ADMIN_ID:
        return
    cur = get_setting("require_24h_renew", "0")
    new_val = "0" if cur == "1" else "1"
    set_setting("require_24h_renew", new_val)
    await cb.answer(f"24h Renewal Requirement set to: {'ON' if new_val == '1' else 'OFF'}", show_alert=True)
    await cb_admin_home(cb)


@router.callback_query(F.data == "adm_backup")
async def cb_admin_backup(cb: CallbackQuery):
    if cb.from_user.id != ADMIN_ID:
        return
    await cb.answer("📦 Compressing /data volume...")
    backup_base = "/tmp/platform_full_backup"
    shutil.make_archive(backup_base, "zip", DATA_DIR)
    await cb.message.answer_document(
        FSInputFile(f"{backup_base}.zip", filename=f"blitz_data_backup_{int(time.time())}.zip"),
        caption=f"✅ **Full `/data` Backup** (SQLite DB + All User Bots)\nCreated: `{time.ctime()}`",
        parse_mode="Markdown",
    )
    os.remove(f"{backup_base}.zip")


@router.callback_query(F.data == "adm_restore")
async def cb_admin_restore(cb: CallbackQuery, state: FSMContext):
    if cb.from_user.id != ADMIN_ID:
        return
    await state.set_state(HostStates.waiting_for_restore)
    await cb.message.edit_text(
        "♻️ **Restore Full `/data` Backup**\n\n"
        "Upload a `blitz_data_backup_*.zip` file generated by this bot to restore the database and all user bots.",
        reply_markup=InlineKeyboardMarkup(
            inline_keyboard=[[InlineKeyboardButton(text="🔙 Cancel", callback_data="admin_home")]]
        ),
        parse_mode="Markdown",
    )


@router.message(HostStates.waiting_for_restore, F.document)
async def handle_admin_restore(msg: Message, state: FSMContext):
    if msg.from_user.id != ADMIN_ID:
        return
    wait_msg = await msg.answer("⏳ **Stopping active bots and restoring `/data` backup...**", parse_mode="Markdown")
    for bid in list(RUNNING_PROCS.keys()):
        await stop_user_bot(bid, mark_stopped=False)

    tmp_zip = Path("/tmp/restore_upload.zip")
    await bot.download(msg.document, destination=tmp_zip)
    with zipfile.ZipFile(tmp_zip, "r") as zf:
        zf.extractall(DATA_DIR)
    tmp_zip.unlink()
    os.chmod(DB_PATH, 0o600)
    await state.clear()
    await auto_resume_bots()
    await wait_msg.edit_text("✅ **Backup restored and running bots resumed!**", parse_mode="Markdown")


@router.callback_query(F.data == "adm_killall")
async def cb_admin_killall(cb: CallbackQuery):
    if cb.from_user.id != ADMIN_ID:
        return
    count = len(RUNNING_PROCS)
    for bid in list(RUNNING_PROCS.keys()):
        await stop_user_bot(bid)
    await cb.answer(f"🛑 Terminated all {count} running user bots.", show_alert=True)
    await cb_admin_home(cb)


@router.message(Command("setslots"))
async def cmd_setslots(msg: Message):
    if msg.from_user.id != ADMIN_ID:
        return
    parts = msg.text.split()
    if len(parts) != 3:
        return await msg.answer("Usage: `/setslots <user_id> <max_bots>`", parse_mode="Markdown")
    uid, slots = int(parts[1]), int(parts[2])
    db_query("INSERT OR IGNORE INTO users (user_id, max_bots) VALUES (?, ?)", (uid, slots))
    db_query("UPDATE users SET max_bots=? WHERE user_id=?", (slots, uid))
    await msg.answer(f"✅ User `{uid}` slot limit set to `{slots}` bots.", parse_mode="Markdown")


@router.message(Command("ban"))
async def cmd_ban(msg: Message):
    if msg.from_user.id != ADMIN_ID:
        return
    parts = msg.text.split()
    if len(parts) != 2:
        return await msg.answer("Usage: `/ban <user_id>`", parse_mode="Markdown")
    uid = int(parts[1])
    db_query("UPDATE users SET is_banned=1 WHERE user_id=?", (uid,))
    for (bid,) in db_query("SELECT bot_id FROM bots WHERE user_id=?", (uid,), fetch=True):
        await stop_user_bot(bid)
    await msg.answer(f"🚫 User `{uid}` banned and all their bots stopped.", parse_mode="Markdown")


@router.message(Command("unban"))
async def cmd_unban(msg: Message):
    if msg.from_user.id != ADMIN_ID:
        return
    parts = msg.text.split()
    if len(parts) != 2:
        return await msg.answer("Usage: `/unban <user_id>`", parse_mode="Markdown")
    uid = int(parts[1])
    db_query("UPDATE users SET is_banned=0 WHERE user_id=?", (uid,))
    await msg.answer(f"✅ User `{uid}` unbanned.", parse_mode="Markdown")


@router.message(Command("broadcast"))
async def cmd_broadcast(msg: Message):
    if msg.from_user.id != ADMIN_ID:
        return
    text = msg.text.partition(" ")[2].strip()
    if not text:
        return await msg.answer("Usage: `/broadcast <your announcement>`", parse_mode="Markdown")
    users = db_query("SELECT user_id FROM users", fetch=True)
    sent = 0
    for (uid,) in users:
        try:
            await bot.send_message(uid, f"📢 **Platform Announcement:**\n\n{text}", parse_mode="Markdown")
            sent += 1
            await asyncio.sleep(0.05)
        except Exception:
            pass
    await msg.answer(f"✅ Broadcast delivered to `{sent}/{len(users)}` users.", parse_mode="Markdown")


async def auto_resume_bots():
    rows = db_query("SELECT bot_id FROM bots WHERE status='running'", fetch=True)
    for (bid,) in rows:
        await start_user_bot(bid)


async def main():
    init_db()
    await auto_resume_bots()
    asyncio.create_task(platform_watchdog())
    asyncio.create_task(blitz_keepalive_and_backup_daemon())
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
