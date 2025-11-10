# =========================
# Anonymessage — app_v9.py
# Stable Pro + Premium v1.1 — Payslip Reading + Region Logic
# =========================

import streamlit as st
import time, random, hashlib, hmac, json, os, re
from datetime import datetime, timedelta, timezone, date
from typing import Dict, List, Optional

# Password hashing
def hash_pw(p: str) -> str:
    return hashlib.sha256(p.encode()).hexdigest()

# ---------------------------------------------------------
# OCR + PDF PARSING UTILITIES
# ---------------------------------------------------------

def try_import_pdf_first():
    """Try import pdfplumber first (best)."""
    try:
        import pdfplumber
        return pdfplumber
    except:
        return None

def try_import_ocr_image():
    """Try import OCR fallback (pytesseract)."""
    try:
        import pytesseract
        return pytesseract
    except:
        return None

def extract_text_from_pdf(file):
    """
    Attempt to extract text from a PDF using pdfplumber.
    Returns string or None.
    """
    pdfplumber = try_import_pdf_first()
    if pdfplumber is None:
        return None

    try:
        import io
        data = file.read()
        with pdfplumber.open(io.BytesIO(data)) as pdf:
            txt = ""
            for page in pdf.pages:
                txt += page.extract_text() or ""
        return txt
    except:
        return None


def extract_text_from_image(file):
    """
    OCR extraction if available; else None.
    """
    pyt = try_import_ocr_image()
    if pyt is None:
        return None
    try:
        from PIL import Image
        img = Image.open(file)
        return pyt.image_to_string(img)
    except:
        return None


# ---------------------------------------------------------
# SIMPLE PAYSLIP PARSER (regex + fuzzy variations)
# ---------------------------------------------------------

def parse_payslip_text(text: str):
    """
    Extract: rate, contract hours, worked hours, ot_rate,
             gross, net, tax, ni.
    All optional — returns dict.
    """
    out = {}
    if not text:
        return out

    # normalise
    clean = re.sub(r"[£$,]", "", text, flags=re.I)

    # fuzzy regex list
    patterns = {
        "rate": r"(hourly.*?rate|basic.*?rate).*?(\d+\.\d+)",
        "hours": r"(hours.*?(worked|wk)|hrs).*?(\d+\.\d+)",
        "contract": r"(contract.*?hours|std.*?hours).*?(\d+\.\d+)",
        "ot_rate": r"(overtime.*?rate|ot.*?rate).*?(\d+\.\d+)",
        "gross": r"(gross.*?pay).*?(\d+\.\d+)",
        "net": r"(net.*?pay).*?(\d+\.\d+)",
        "ni": r"(national.*?insurance|ni).*?(\d+\.\d+)",
        "tax": r"(tax|paye).*?(\d+\.\d+)",
    }

    for key, pat in patterns.items():
        m = re.search(pat, clean, flags=re.I)
        if m:
            # handle groups where match number is group 2 or 3
            try:
                val = m.group(2)
            except:
                try:
                    val = m.group(3)
                except:
                    val = None
            if val:
                try:
                    out[key] = float(val)
                except:
                    pass

    return out


# ---------------------------------------------------------
# REGION RULES
# ---------------------------------------------------------

REGIONS = ["UK", "US", "EU", "Other"]

# Defaults per region
REGION_DEFAULTS = {
    "UK": {
        "tax": 0.20,
        "ni": 0.12,
        "ot_multiplier": 1.5,
        "contract": 37.5,
    },
    "US": {
        "tax": 0.18,
        "ni": 0.075,
        "ot_multiplier": 1.5,
        "contract": 40,
    },
    "EU": {
        "tax": 0.23,
        "ni": 0.10,
        "ot_multiplier": 1.25,
        "contract": 38,
    },
    "Other": {
        "tax": 0.20,
        "ni": 0.12,
        "ot_multiplier": 1.5,
        "contract": 37.5,
    }
}


# ---------------------------------------------------------
# BASE APP CONFIG
# ---------------------------------------------------------

st.set_page_config(
    page_title="Anonymessage",
    layout="wide",
    initial_sidebar_state="collapsed"
)

APP_TITLE = "Anonymessage"

ADMIN_EMAIL = "tonyrowlandson2014@gmail.com"
ADMIN_PASSWORD = "Thebattleof1066!"

SECRET_KEY = "change_this_to_random_secret"
SK = lambda k: f"am_{k}"


# ---------------------------------------------------------
# TOKEN / SIGNING
# ---------------------------------------------------------

def _sign(s: str) -> str:
    return hmac.new(SECRET_KEY.encode(), s.encode(), hashlib.sha256).hexdigest()

def make_token(u: str, adm: bool, pre: bool, days: int = 7) -> str:
    exp = int((datetime.now(timezone.utc) + timedelta(days=days)).timestamp())
    payload = json.dumps(
        {"u": u, "adm": int(adm), "pre": int(pre), "exp": exp},
        separators=(",", ":"), sort_keys=True
    )
    return f"{payload}.{_sign(payload)}"

def parse_token(tok: str):
    try:
        payload, sig = tok.rsplit(".", 1)
        if _sign(payload) != sig:
            return None
        data = json.loads(payload)
        if int(data.get("exp", 0)) < int(datetime.now(timezone.utc).timestamp()):
            return None
        return data
    except:
        return None

def set_qtoken(tok: Optional[str]):
    qp = dict(st.query_params)
    if tok is None:
        qp.pop("t", None)
        st.query_params.clear()
        if qp:
            st.query_params.update(qp)
    else:
        qp["t"] = tok
        st.query_params.clear()
        st.query_params.update(qp)


# ---------------------------------------------------------
# NOTES / TOASTS
# ---------------------------------------------------------

def add_note(msg: str, level: str = "info"):
    st.session_state[SK("notes")].append({"msg": msg, "lev": level})

def show_notes():
    for n in st.session_state.get(SK("notes"), []):
        lev = n.get("lev", "info")
        if hasattr(st, lev):
            getattr(st, lev)(n["msg"])
        else:
            st.info(n["msg"])
    st.session_state[SK("notes")] = []


# ---------------------------------------------------------
# UTILS
# ---------------------------------------------------------

def online_now() -> int:
    t = int(time.time() // 60)
    return 4 + (t * 7 + datetime.now().hour * 3) % 11

def anon_handle(existing: set) -> str:
    for _ in range(500):
        n = random.randint(102, 500)
        name = f"Anonymous_{n}"
        if name not in existing:
            return name
    return f"Anonymous_{random.randint(1000,9999)}"


def get_user(email: str):
    users = st.session_state[SK("users")]
    return users.get(email)

def create_user(email: str, password: str):
    users = st.session_state[SK("users")]

    if email in users:
        return False  # already exists

    users[email] = {
        "password_hash": hash_pw(password),
        "premium": False,
        "rep": 0,
        "xp": 0,
        "badges": [],
        "posts": 0,
        "last_ai_reply_ts": 0,
    }
    return True


def set_premium(u: str, v: bool = True):
    get_user(u)["premium"] = v

def award_xp(u: str, xp: int = 1):
    get_user(u)["xp"] += max(0, xp)

def change_rep(u: str, delta: int):
    get_user(u)["rep"] += delta


def blur_text(s: str) -> str:
    ZWSP = "\u200B"
    return ZWSP.join(list(s))


# ---------------------------------------------------------
# STORAGE INITIALISATION
# ---------------------------------------------------------

def init_store():
    ss = st.session_state
    defaults = {
        "users": {},
        "threads": [],
        "prem_threads": [],
        "polls": [],
        "reports": [],
        "dms": {},
        "events": {"region": "UK", "items": []},
        "shifts": [],
        "settings": {
            "remember_days": 7,
            "public_view": False,
            "maintenance": False,
            "language_filter": False,
            "default_region": "UK",
        },
        "notes": [],
        "last_fact_date": "",
        "last_fact_text": "",
        "nav": "Feed",
        "ai_last_post_ts": 0,
    }

    for k, v in defaults.items():
        if SK(k) not in ss:
            ss[SK(k)] = v

    if not ss[SK("users")]:
        for n in range(102, 151):
            ss[SK("users")][f"Anonymous_{n}"] = {
                "premium": n % 7 == 0,
                "rep": (n * 37) % 301,
                "xp": (n * 11) % 90,
                "badges": [],
                "posts": 0,
                "last_ai_reply_ts": 0,
            }
        ss[SK("users")]["Anonymous_2 (AI)"] = {
            "premium": True,
            "rep": 0,
            "xp": 0,
            "badges": [],
            "posts": 0,
            "last_ai_reply_ts": 0,
        }
# ---------------------------------------------------------
# AUTH
# ---------------------------------------------------------

def require_auth() -> bool:
    if SK("auth") in st.session_state:
        return True
    tok = st.query_params.get("t")
    if not tok:
        return False
    data = parse_token(tok)
    if not data:
        return False
    u, adm, pre = data["u"], bool(data["adm"]), bool(data["pre"])
    get_user(u)
    set_premium(u, pre)
    st.session_state[SK("auth")] = {
        "username": u,
        "is_admin": adm,
        "is_premium": pre,
    }
    return True

# ---------------------------------------------------------
# LOGOUT
# ---------------------------------------------------------
def logout():
    if SK("auth") in st.session_state:
        del st.session_state[SK("auth")]

    if "remember_me" in st.session_state:
        del st.session_state["remember_me"]

    set_qtoken(None)
    add_note("Logged out.", "success")
    st.rerun()

def do_login_ui():
    st.title(APP_TITLE)

    st.markdown(
        """
        <div style='background:#0b6e4f22;padding:8px 12px;border-radius:8px;'>
        <marquee>Welcome to Anonymessage • Be kind • Stay Anonymous • No doxxing</marquee>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div style='background:#222;padding:8px;border-radius:8px;margin-top:6px;'>
        <b>App Rules:</b> No harassment • No personal data • Keep it respectful
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.subheader("Log in")

    email = st.text_input("Email (not public)").strip().lower()
    pwd = st.text_input("Password", type="password")
    remember = st.checkbox("Remember me for 7 days", value=True)

    if st.button("Log in"):

        # ✅ Admin check
        if email == ADMIN_EMAIL.lower() and pwd == ADMIN_PASSWORD:
            st.session_state["auth"] = {
                "username": "Adminious_1",
                "is_admin": True,
                "is_premium": True,
            }

            if remember:
                tok = make_token("Adminious_1", True, True)
                set_qtoken(tok)

            add_note("Logged in as Admin.", "success")
            st.rerun()
            return

        # ✅ Normal users must exist
        users = st.session_state[SK("users")]

        if email not in users:
            st.error("Incorrect email or password")
            return

        stored_user = users[email]

        # ✅ Check password hash
        if stored_user.get("password_hash") != hash_pw(pwd):
            st.error("Incorrect email or password")
            return

        # ✅ Login success
        st.session_state["auth"] = {
            "username": email,
            "is_admin": False,
            "is_premium": stored_user.get("premium", False),
        }

        if remember:
            tok = make_token(email, False, stored_user.get("premium", False))
            set_qtoken(tok)

        add_note("Logged in.", "success")
        st.rerun()

# ---------------------------------------------------------
# HEADER
# ---------------------------------------------------------

def header(auth):
    st.title(APP_TITLE)
    c1, c2, c3 = st.columns([2, 3, 2])

    with c1:
        name = auth["username"]
        if auth.get("is_admin"):
            name += " (Admin)"
        st.caption(f"Logged in as: {name}")
        st.caption(f"Online now: ~{online_now()}")
        if st.session_state[SK("settings")]["maintenance"]:
            st.warning("🚧 Scheduled Maintenance — non-admin posting disabled.")

    with c2:
        st.markdown(
            """
            <div style='background:#0b6e4f22;padding:8px 12px;border-radius:8px;'>
            <marquee>Welcome to Anonymessage • Be kind • Stay Anonymous • Report issues via Support tab</marquee>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            """
            <div style='margin-top:6px;background:#222;padding:8px;border-radius:8px;'>
            <b>App Rules:</b> No harassment • No personal data • Keep it helpful
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c3:
        if st.button("Logout"):
            logout()

    show_notes()


# ---------------------------------------------------------
# DAILY FACT
# ---------------------------------------------------------

FACTS = [
    "Frozen stock should stay below −18 °C to maintain quality.",
    "Sound horn at aisle ends when driving a reach truck.",
    "FIFO rotation prevents ageing stock.",
    "Keep forks low when travelling to avoid rack strikes.",
    "Avoid pallet overhang to maintain stability.",
    "Condensation can fog scanners after chill→ambient moves.",
]

def ensure_daily_fact():
    today = datetime.utcnow().strftime("%Y-%m-%d")
    if st.session_state[SK("last_fact_date")] == today:
        return
    st.session_state[SK("last_fact_date")] = today
    st.session_state[SK("last_fact_text")] = random.choice(FACTS)


# ---------------------------------------------------------
# THREADS
# ---------------------------------------------------------

def _language_ok(s: str) -> bool:
    if not st.session_state[SK("settings")]["language_filter"]:
        return True
    banned = ["idiot", "slur", "hate"]
    return not any(b in s.lower() for b in banned)


def _smart_tags(title: str, body: str) -> List[str]:
    txt = f"{title} {body}".lower()
    tags = []
    if any(k in txt for k in ["pay", "overtime", "wage"]):
        tags.append("pay")
    if any(k in txt for k in ["shift", "cover"]):
        tags.append("shifts")
    if any(k in txt for k in ["manager", "policy"]):
        tags.append("workplace")
    if any(k in txt for k in ["football", "match", "prem"]):
        tags.append("sports")
    if not tags:
        tags.append("general")
    return tags


def _can_post(auth) -> bool:
    if st.session_state[SK("settings")]["maintenance"] and not auth.get("is_admin"):
        add_note("Posting disabled during maintenance.", "warning")
        return False
    return True


def _after_user_post(author: str):
    u = get_user(author)
    u["posts"] += 1
    award_xp(author, 2)
    if u["posts"] == 5 and not u["premium"]:
        set_premium(author, True)
        add_note("🎉 24-hour Premium trial unlocked!", "success")


def post_thread(store_key: str, author: str, title: str, body: str):
    tid = hashlib.md5(f"{store_key}{author}{title}{time.time()}".encode()).hexdigest()[:10]
    st.session_state[store_key].append(
        {
            "id": tid,
            "author": author,
            "title": title.strip(),
            "body": body.strip(),
            "ts": int(time.time()),
            "votes": 0,
            "replies": [],
            "tags": _smart_tags(title, body),
        }
    )


def render_thread(t, auth, store_key, show_report=True, allow_vote=True):
    when = datetime.fromtimestamp(t["ts"]).strftime("%Y-%m-%d %H:%M")
    st.markdown(f"### {t['title']}")
    st.caption(f"by {t['author']} • {when} • 👍 {t['votes']} • Tags: {', '.join(t.get('tags', []))}")

    c1, c2, c3 = st.columns([1, 1, 6])
    if allow_vote and c1.button("👍", key=f"up_{t['id']}"):
        t["votes"] += 1
        change_rep(t["author"], +1)
        st.rerun()

    if show_report and c2.button("🚩 Report", key=f"rp_{t['id']}"):

        st.session_state[SK("reports")].append(
            {
                "id": hashlib.md5(f"rep{time.time()}".encode()).hexdigest()[:8],
                "user": auth["username"],
                "details": t["title"],
                "status": "open",
                "ts": int(time.time()),
            }
        )
        st.success("Reported.")

    st.write(t["body"])

    reply = st.text_input("Reply", key=f"reply_{t['id']}")
    if st.button("Send Reply", key=f"send_{t['id']}"):
        if not _can_post(auth):
            return
        if not _language_ok(reply):
            add_note("Language filter blocked reply.", "warning")
            st.rerun()
        t["replies"].append(
            {"a": auth["username"], "b": reply.strip(), "ts": int(time.time())}
        )
        award_xp(auth["username"], 1)
        st.rerun()

    if t["replies"]:
        st.caption("Replies:")
        for m in t["replies"]:
            ts = datetime.fromtimestamp(m["ts"]).strftime("%Y-%m-%d %H:%M")
            st.markdown(f"- **{m['a']}** ({ts}): {m['b']}")

    st.divider()


# ---------------------------------------------------------
# AI AUTOREPLY
# ---------------------------------------------------------

def try_ai_autoreplies():
    now = int(time.time())
    if now - st.session_state[SK("ai_last_post_ts")] < 5 * 3600:
        return

    candidates = []
    for t in st.session_state[SK("threads")]:
        age = now - t["ts"]
        if age >= 5 * 3600 and len(t["replies"]) == 0 and t.get("_ai_answered") != True:
            candidates.append(t)

    if not candidates:
        return

    t = random.choice(candidates)
    pool = [
        "Interesting point — what outcome are you hoping for?",
        "Thanks for sharing. Have you tried HR?",
        "I see both sides. Maybe trial shift swap?",
        "Maybe run a quick poll?",
        "Good question — what’s next step?",
    ]
    ai_user = "Anonymous_2 (AI)"
    t["replies"].append({"a": ai_user, "b": random.choice(pool), "ts": now})
    t["_ai_answered"] = True
    st.session_state[SK("ai_last_post_ts")] = now


# ---------------------------------------------------------
# NAV BAR
# ---------------------------------------------------------

NAV_ITEMS = [
    "Feed",
    "Weekly Spotlight",
    "Polls",
    "Advice Corner",
    "Workplace Banter",
    "1-Min Chat",
    "Premium Lounge",
    "DMs",
    "Colleague Events",
    "Shifts",
    "Overtime",
    "Leaderboard",
    "White Pages",
    "Support",
    "Lineage News & Updates",
    "Reports (Admin)",
    "Settings",
]

def nav_bar():
    st.markdown("### ")
    st.session_state[SK("nav")] = st.radio(
        "Navigation",
        NAV_ITEMS,
        index=(
            NAV_ITEMS.index(st.session_state[SK("nav")])
            if st.session_state[SK("nav")] in NAV_ITEMS
            else 0
        ),
        key=SK("nav_radio"),
        horizontal=True,
        label_visibility="collapsed",
    )
    st.markdown("---")
# ---------------------------------------------------------
# FEED
# ---------------------------------------------------------

def tab_feed(auth):
    ensure_daily_fact()
    st.subheader("Public Feed")
    st.info(f"💡 Fact of the Shift: {st.session_state[SK('last_fact_text')]}")

    title = st.text_input("Title", key="feed_title")
    body = st.text_area("Message", key="feed_msg")

    if st.button("Post", key="feed_post"):
        if not _can_post(auth):
            return
        if not title.strip():
            add_note("Title required.", "warning")
            st.rerun()
        if not _language_ok(title + " " + body):
            add_note("Language filter blocked this post.", "warning")
            st.rerun()
        post_thread(SK("threads"), auth["username"], title, body)
        _after_user_post(auth["username"])
        st.rerun()

    # Example seed threads (first-time)
    if not st.session_state[SK("threads")]:
        examples = [
            ("Best place nearby for lunch?", "Looking for quick + cheap."),
            ("Shift swap ideas", "Anyone want Fri night for Sun morning?"),
            ("Overtime tips", "How do you decide when OT is worth it?"),
        ]
        for (t, b) in examples:
            post_thread(SK("threads"), "Anonymous_145", t, b)

    for t in sorted(
        st.session_state[SK("threads")], key=lambda x: x["ts"], reverse=True
    ):
        render_thread(t, auth, SK("threads"))

    try_ai_autoreplies()


# ---------------------------------------------------------
# WEEKLY SPOTLIGHT
# ---------------------------------------------------------

def tab_weekly_spotlight():
    st.subheader("Weekly Spotlight")
    threads = st.session_state[SK("threads")]
    if not threads:
        st.info("No posts yet.")
        return
    best = max(threads, key=lambda x: x["votes"])
    st.markdown(f"### {best['title']}")
    st.caption(f"by {best['author']} • 👍 {best['votes']}")
    st.write(best["body"])
    st.success("🎉 Spotlighted post of the week!")


# ---------------------------------------------------------
# POLLS
# ---------------------------------------------------------

def tab_polls(auth):
    st.subheader("Community Polls")

    q = st.text_input("Poll question", key="poll_q")
    o1 = st.text_input("Option 1", key="poll_o1")
    o2 = st.text_input("Option 2", key="poll_o2")

    if st.button("Create Poll", key="poll_create"):
        if not _can_post(auth):
            return
        if not (q.strip() and o1.strip() and o2.strip()):
            add_note("Enter a question + 2 options.", "warning")
            st.rerun()

        pid = hashlib.md5(f"{q}{time.time()}".encode()).hexdigest()[:8]
        st.session_state[SK("polls")].append(
            {
                "id": pid,
                "question": q.strip(),
                "options": [{"t": o1.strip(), "v": 0}, {"t": o2.strip(), "v": 0}],
                "author": auth["username"],
                "ts": int(time.time()),
            }
        )
        st.success("Poll created.")
        st.rerun()

    for p in st.session_state[SK("polls")]:
        st.markdown(f"**{p['question']}**")
        tot = sum(o["v"] for o in p["options"]) or 1
        for i, o in enumerate(p["options"]):
            pct = int((o["v"] / tot) * 100)
            if st.button(f"Vote {o['t']}", key=f"vote_{p['id']}_{i}"):
                o["v"] += 1
                st.rerun()
            st.progress(pct / 100)
            st.caption(f"{o['t']} — {pct}%")
        st.divider()


# ---------------------------------------------------------
# REUSABLE ROOM TEMPLATE
# ---------------------------------------------------------

def _room_template(auth, store_key: str, room_title: str, post_label: str, min_len=0, max_len=None):
    st.subheader(room_title)

    title = st.text_input("Title", key=f"{store_key}_title")
    body = st.text_area(post_label, key=f"{store_key}_msg")

    if max_len is not None and body and len(body) > max_len:
        st.warning(f"Limit: {max_len} characters.")

    if st.button("Post", key=f"{store_key}_post"):
        if not _can_post(auth):
            return
        content = (title + " " + body) if (title or body) else ""
        if min_len and len(content.strip()) < min_len:
            add_note(f"Min {min_len} chars.", "warning")
            st.rerun()
        if not _language_ok(content):
            add_note("Language filter blocked post.", "warning")
            st.rerun()
        post_thread(SK("threads"), auth["username"], f"[{room_title}] {title}", body)
        _after_user_post(auth["username"])
        st.success("Posted!")
        st.rerun()

    tag = f"[{room_title}] "
    posts = [t for t in st.session_state[SK("threads")] if t["title"].startswith(tag)]
    if not posts:
        st.info("No posts yet.")
    for t in sorted(posts, key=lambda x: x["ts"], reverse=True):
        render_thread(t, auth, SK("threads"))


# ---------------------------------------------------------
# ROOM TABS
# ---------------------------------------------------------

def tab_advice(auth):
    _room_template(auth, "advice", "Advice Corner", "Ask advice", min_len=8, max_len=500)

def tab_banter(auth):
    _room_template(auth, "banter", "Workplace Banter", "Share something funny", max_len=280)

def tab_one_min(auth):
    st.subheader("1-Min Chat")
    st.caption("Quick-fire posts. Keep it short!")
    _room_template(auth, "onemin", "1-Min Chat", "Say it!", max_len=240)

    # ---------------------------------------------------------
# DMs — 60-second private rooms
# ---------------------------------------------------------
def tab_dms(auth):
    st.subheader("Anonymous DMs")
    st.caption("Invite a user to a 60-second private chat.")

    if SK("dms") not in st.session_state:
        st.session_state[SK("dms")] = {}

    all_users = sorted(list(st.session_state[SK("users")].keys()))
    tgt = st.selectbox("Invite user", all_users, key="dm_target")

    if st.button("Create DM Room", key="dm_new"):
        rid = "dm_" + hashlib.md5(f"{auth['username']}{tgt}{time.time()}".encode()).hexdigest()[:8]
        st.session_state[SK("dms")][rid] = {
            "users": [auth["username"], tgt],
            "expires": int(time.time()) + 60,
            "msgs": []
        }
        st.success("Room created for 60 seconds.")
        st.rerun()

    now = int(time.time())
    for rid, rm in list(st.session_state[SK("dms")].items()):
        if rm["expires"] <= now:
            del st.session_state[SK("dms")][rid]
            continue

        if auth["username"] not in rm["users"] and not auth.get("is_admin"):
            continue

        st.markdown(
            f"**Room {rid}** • Expires in {rm['expires']-now}s • Users: "
            f"{', '.join(rm['users'])}"
        )

        msg = st.text_input("Message", key=f"dm_msg_{rid}")
        if st.button("Send", key=f"dm_send_{rid}") and msg.strip():
            rm["msgs"].append({
                "a": auth["username"],
                "b": msg.strip(),
                "ts": int(time.time())
            })
            st.rerun()

        for m in rm["msgs"]:
            ts = datetime.fromtimestamp(m["ts"]).strftime("%H:%M:%S")
            st.markdown(f"- **{m['a']}** ({ts}): {m['b']}")

        st.divider()


# ---------------------------------------------------------
# PREMIUM LOUNGE
# ---------------------------------------------------------

def tab_premium(auth):
    st.subheader("Premium Lounge 💎")

    # show approx. active
    active_count = online_now() // 2 + sum(
        1 for u in st.session_state[SK("users")].values() if u.get("premium")
    )
    st.info(f"Active in lounge now: {active_count}")

    # auto seed a realistic number of posts
    def seed_premium_threads(active_count: int):
        needed = max(0, min(active_count - 2, 6))
        existing = len(st.session_state[SK("prem_threads")])
        to_add = max(0, needed - existing)
        if to_add <= 0:
            return

        examples = [
            ("Rota changes next month?", "Anyone heard if 4-on-4-off returning?"),
            ("Chiller OT worth it?", "Temps brutal lately. Worth chill bonus?"),
            ("Reach truck refresher?", "Rumour about mandatory short refresher — anyone done?"),
            ("Silent rules for swaps?", "Unwritten rule: no last-min swaps? True?"),
            ("New shift manager?", "Mixed feedback — anyone worked with him?"),
            ("Pallet wrapping hack", "Double bind bottom → corner pull → top finish."),
        ]

        for i in range(to_add):
            title, body = examples[i % len(examples)]
            post_thread(SK("prem_threads"), "Anonymous_145", title, body)

    seed_premium_threads(active_count)

    # show or unlock
    if not auth.get("is_premium"):
        st.info("Premium required to read/post.")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Activate Premium (Demo)"):
                auth["is_premium"] = True
                set_premium(auth["username"], True)
                add_note("Premium (demo) activated!", "success")
                st.rerun()
        with c2:
            st.caption("💎 £0.99/mo • £2.49/3mo (15% off)")
        return

    title = st.text_input("Start a premium discussion", key="prem_title")
    body = st.text_area("Message", key="prem_msg")

    if st.button("Post to Premium", key="prem_post"):
        if not _can_post(auth):
            return
        if not title.strip():
            add_note("Title required.", "warning")
            st.rerun()
        if not _language_ok(title + " " + body):
            add_note("Language filter blocked.", "warning")
            st.rerun()
        post_thread(SK("prem_threads"), auth["username"], title, body)
        _after_user_post(auth["username"])
        st.rerun()

    for t in sorted(
        st.session_state[SK("prem_threads")], key=lambda x: x["ts"], reverse=True
    ):
        render_thread(t, auth, SK("prem_threads"), show_report=False)
# ---------------------------------------------------------
# COLLEAGUE EVENTS
# ---------------------------------------------------------

def tab_events(auth):
    st.subheader("Colleague Events")

    regions = REGIONS
    current_region = st.session_state[SK("events")].get("region", "UK")
    r_ix = regions.index(current_region) if current_region in regions else 0

    region = st.selectbox("Region", options=regions, index=r_ix)
    st.session_state[SK("events")]["region"] = region

    with st.form("events_new"):
        d = st.date_input("Date", value=date.today())
        title = st.text_input("Title")
        place = st.text_input("Location (optional)")
        desc = st.text_area("Description (optional)")
        ok = st.form_submit_button("Add Event")

    if ok and title.strip():
        st.session_state[SK("events")]["items"].append(
            {
                "date": str(d),
                "title": title.strip(),
                "place": place.strip(),
                "desc": desc.strip(),
                "region": region,
            }
        )
        st.success("✅ Event added.")

    items = sorted(st.session_state[SK("events")]["items"], key=lambda x: x["date"])
    if not items:
        st.info("No events yet.")
    else:
        for e in items:
            st.markdown(
                f"**{e['date']}** — {e['title']}  "
                f"{('• ' + e['place']) if e['place'] else ''}"
            )
            if e["desc"]:
                st.caption(e["desc"])
            st.divider()


# ---------------------------------------------------------
# SHIFTS
# ---------------------------------------------------------

def tab_shifts(auth):
    st.subheader("Shifts / Cover Needed")

    with st.form("shift_new"):
        d = st.date_input("Date", value=date.today())
        start = st.time_input("Start time")
        end = st.time_input("End time")
        role = st.text_input("Role")
        contact = st.text_input("Public contact name")
        note = st.text_area("Notes (optional)")
        ok = st.form_submit_button("Post Shift")

    if ok and contact.strip():
        st.session_state[SK("shifts")].append(
            {
                "date": str(d),
                "start": str(start),
                "end": str(end),
                "role": role,
                "contact": contact,
                "note": note,
            }
        )
        st.success("✅ Shift posted.")
        st.rerun()

    for s in sorted(st.session_state[SK("shifts")], key=lambda x: x["date"], reverse=True):
        st.markdown(
            f"**{s['date']} {s['start']}-{s['end']}** • {s['role']} • Contact: {s['contact']}"
        )
        if s["note"]:
            st.caption(s["note"])
        st.divider()

    st.markdown("### Shift Patterns at Lineage")
    st.write("- **Mon–Fri** (fixed weekdays)")
    st.write("- **Sun–Thu** (nights/ops dependent)")
    st.write("- **4-on / 4-off** (very common)")
    st.write("- **3-on / 4-off** (team-dependent)")
    st.caption("Core patterns stay fixed — **Overtime** is what changes week-to-week.")


# ---------------------------------------------------------
# OVERTIME — SMART CALCULATOR (auto-read payslip + region)
# ---------------------------------------------------------

def tab_overtime():
    st.subheader("Overtime Sweet-Spot Calculator")

    # ---- Region selection ----
    st.markdown("### 🌍 Region")
    region = st.selectbox("Select region", REGIONS)
    defaults = REGION_DEFAULTS.get(region, REGION_DEFAULTS["Other"])

    # ---- Payslip upload ----
    st.markdown("### 📄 Upload Payslip (Optional)")
    uploaded = st.file_uploader("Upload PDF / Image", type=["pdf", "png", "jpg", "jpeg"])

    parsed = {}
    text = None

    if uploaded:
        with st.spinner("🔎 Reading payslip…"):
            if uploaded.name.lower().endswith(".pdf"):
                text = extract_text_from_pdf(uploaded)
            else:
                text = extract_text_from_image(uploaded)

        if text:
            parsed = parse_payslip_text(text)
            st.success("✅ Payslip read successfully")
        else:
            st.info("⚠ Could not auto-read. Please enter manually.")

    # ---- Autofill values if present ----
    default_rate    = parsed.get("rate",     14.74)
    default_base    = parsed.get("contract", defaults["contract"])
    default_worked  = parsed.get("hours",    45.0)
    default_ot_rate = parsed.get("ot_rate",  default_rate * defaults["ot_multiplier"])

    # ---- Inputs ----
    st.markdown("### Calculator")
    c1, c2, c3 = st.columns(3)
    with c1:
        rate = st.number_input("Hourly £", min_value=0.0, value=default_rate, key="ot_rate2")
    with c2:
        base = st.number_input("Contract hrs/week", min_value=0.0, value=default_base, key="ot_base2")
    with c3:
        worked = st.number_input("Total hrs worked", min_value=0.0, value=default_worked, key="ot_worked2")

    # OT rate
    ot_rate = default_ot_rate

    # ---- Calculations ----
    ot_hours = max(0.0, worked - base)
    gross = rate * base + ot_rate * ot_hours
    tax = gross * defaults["tax"]
    ni  = gross * defaults["ni"]
    net = gross - tax - ni

    cA, cB, cC = st.columns(3)
    with cA:
        st.metric("OT Hours", f"{ot_hours:.2f}h")
    with cB:
        st.metric("Gross", f"£{gross:.2f}")
    with cC:
        st.metric("Net", f"£{net:.2f}")

    st.caption(
        f"Assumes {defaults['tax']*100:.0f}% income tax + "
        f"{defaults['ni']*100:.0f}% NI • region: {region}"
    )

    if parsed:
        with st.expander("📄 Extracted Data"):
            for k, v in parsed.items():
                st.write(f"**{k}**: {v}")


# ---------------------------------------------------------
# LEADERBOARD
# ---------------------------------------------------------

def tab_leaderboard():
    st.subheader("Public Leaderboard")
    users = st.session_state[SK("users")]

    rows = [
        (u, d["rep"], d["xp"], "💎" if d.get("premium") else "")
        for u, d in users.items()
    ]
    rows.sort(key=lambda r: (-r[1], -r[2], r[0]))

    for i, (u, rep, xp, gem) in enumerate(rows[:50], start=1):
        st.markdown(f"**{i}. {u} {gem}** — Rep: {rep} • XP: {xp}")


# ---------------------------------------------------------
# WHITE PAGES
# ---------------------------------------------------------

def tab_white_pages():
    st.subheader("White Pages")

    st.markdown("### Introduction")
    st.write("Anonymessage is a simple, anonymous discussion app for colleagues and friends.")

    st.markdown("### Mission")
    st.write("Share, ask, support — with privacy + simplicity.")

    st.markdown("### How It Works")
    st.write("Pick a random handle — post publicly or in private rooms.")

    st.markdown("### Privacy")
    st.write("No identifying info. Stay anonymous.")

    st.markdown("### Transparency")
    st.write(
        "We use a small helper AI (**Anonymous_2 (AI)**) that replies when posts "
        "have no responses for 5+ hours."
    )


# ---------------------------------------------------------
# SUPPORT
# ---------------------------------------------------------

def tab_support():
    st.subheader("Help & Support")
    st.write("• FAQ — Coming soon")
    st.write("• Contact — Use Reports tab for moderation issues.")
    st.markdown("---")
    st.caption("Inform the admin with any issues or questions.")


# ---------------------------------------------------------
# LINEAGE NEWS
# ---------------------------------------------------------

def tab_lineage_news():
    st.subheader("Lineage News & Updates")

    headlines = [
        ("Cold-chain demand remains resilient", "Service + reliability focus across UK network"),
        ("Temperature-controlled operations prioritised", "Safety, efficiency + uptime"),
        ("Peak season balancing", "Capacity + service levels maintained"),
        ("Ops recognition", "Industry-wide awards for reliability + safety"),
        ("Outlook stable", "Food/pharma storage remains consistent"),
    ]

    ix = datetime.utcnow().timetuple().tm_yday % len(headlines)
    t, body = headlines[ix]

    st.markdown(f"**{t}**")
    st.write(body)

    if st.button("Next headline"):
        ni = (ix + 1) % len(headlines)
        t2, b2 = headlines[ni]
        st.markdown(f"**{t2}**")
        st.write(b2)

    st.markdown("### Quick Context")
    st.write("- Network supports cold-chain food + pharma")
    st.write("- Core shifts stable (Mon-Fri, Sun-Thu, 4-on/4-off, 3-on/4-off)")
    st.write("- OT flexes with demand")


# ---------------------------------------------------------
# REPORTS (Admin)
# ---------------------------------------------------------

def tab_reports(auth):
    st.subheader("User Reports (Admin)")
    if not auth.get("is_admin"):
        st.info("Admin only.")
        return

    reports = st.session_state[SK("reports")]
    if not reports:
        st.info("No reports.")
        return

    for r in list(reports):
        st.markdown(f"**{r['user']}** reported: {r['details']}")
        if st.button("✅ Resolve", key=f"rep_{r['id']}"):
            reports.remove(r)
            st.rerun()


# ---------------------------------------------------------
# SETTINGS
# ---------------------------------------------------------

def tab_settings(auth):
    st.subheader("Settings")

    s = st.session_state[SK("settings")]

    c1, c2, c3 = st.columns(3)
    with c1:
        s["public_view"] = st.toggle("Admin: View as Public", value=s["public_view"])
        s["maintenance"] = st.toggle(
            "Enable Maintenance Mode", value=s["maintenance"]
        )
    with c2:
        s["language_filter"] = st.toggle(
            "Language Filter (basic)", value=s["language_filter"]
        )
        s["default_region"] = st.selectbox(
            "Default region", REGIONS, index=REGIONS.index(s["default_region"])
        )
    with c3:
        s["remember_days"] = st.number_input(
            "Remember login (days)",
            min_value=1,
            max_value=30,
            value=s["remember_days"],
        )

    st.success("✅ Settings saved.")

    st.markdown("---")
    st.markdown("### Legal Pages (Markdown)")
    st.caption("Place files in `legal_pages/terms.md`, `privacy.md`, `fairuse.md`")

    root = "legal_pages"
    doc_map = [
        ("Terms of Service", "terms.md"),
        ("Privacy Policy", "privacy.md"),
        ("Fair Use Disclaimer", "fairuse.md"),
    ]

    for title, fname in doc_map:
        path = os.path.join(root, fname)
        st.markdown(f"**{title}**")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                st.markdown(f.read())
        else:
            st.info(f"`{path}` not found.")
# ---------------------------------------------------------
# MAIN ROUTER
# ---------------------------------------------------------

def main():
    init_store()

    # ---- Auth ----
    if not require_auth():
        do_login_ui()
        return

    auth = st.session_state[SK("auth")]

    # ---- Header + Nav ----
    header(auth)
    nav_bar()

    # ---- Public view (admin simulation) ----
    is_public_view = (
        st.session_state[SK("settings")]["public_view"]
        and auth.get("is_admin")
    )
    if is_public_view:
        st.info("✅ Viewing as PUBLIC (Admin simulation).")

    # ---- Route ----
    cur = st.session_state[SK("nav")]

    if cur == "Feed":
        tab_feed(auth)

    elif cur == "Weekly Spotlight":
        tab_weekly_spotlight()

    elif cur == "Polls":
        tab_polls(auth)

    elif cur == "Advice Corner":
        tab_advice(auth)

    elif cur == "Workplace Banter":
        tab_banter(auth)

    elif cur == "1-Min Chat":
        tab_one_min(auth)

    elif cur == "Premium Lounge":
        tab_premium(auth)

    elif cur == "DMs":
        tab_dms(auth)

    elif cur == "Colleague Events":
        tab_events(auth)

    elif cur == "Shifts":
        tab_shifts(auth)

    elif cur == "Overtime":
        tab_overtime()

    elif cur == "Leaderboard":
        tab_leaderboard()

    elif cur == "White Pages":
        tab_white_pages()

    elif cur == "Support":
        tab_support()

    elif cur == "Lineage News & Updates":
        tab_lineage_news()

    elif cur == "Reports (Admin)":
        tab_reports(auth)

    elif cur == "Settings":
        tab_settings(auth)


# ---------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------

if __name__ == "__main__":
    main()
