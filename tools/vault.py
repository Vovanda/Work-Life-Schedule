"""Правка дел хозяйства: зашифрованные записи плюс зашифрованный индекс.

Всё, что показывает сайт, лежит здесь — публичного слоя у него нет:

    my-data.json   {"v": 1, "items": ["<base64>", ...]}
    index.json     {"v": 1, "salt": "<base64>", "index": "<base64>"}

Каждая запись — свой фрагмент со своим вектором. Новая встаёт одной строкой,
правка меняет одну строку, соседние остаются байт в байт теми же.

Индекс зашифрован целиком и читается первым: внутри пары «дата — позиция
фрагмента». По нему сайт берёт нужный отрезок и расшифровывает только его,
не трогая остальной файл. Наружу при этом не торчит ни одной даты.

Соль лежит в index.json — он и открывается первым.

Пароль: --password, SCHEDULE_PASSWORD, .env рядом с репозиторием или спросим.

    python tools/vault.py list
    python tools/vault.py list --from 03.09.2026 --to 08.09.2026
    python tools/vault.py add --subject "Подоить коз" --date 03.09.2026 --time 19:45 \
        --type Дойка --repeat пн,вт,ср,чт,пт,сб,вс --until 08.09.2026
    python tools/vault.py edit --id 5019e955 --time 20:00
    python tools/vault.py rm --id 5019e955
    python tools/vault.py import --file seed.json   # первичная заливка распорядка
"""

import argparse
import base64
import getpass
import json
import os
import re
import secrets
import sys
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DATA_FILE = "my-data.json"
INDEX_FILE = "index.json"
# Локальный слой: выдуманные записи для проверки вёрстки. Лежат отдельно и
# закрыты .gitignore, поэтому в прод попасть не могут.
LOCAL_DATA_FILE = "my-data.local.json"
LOCAL_INDEX_FILE = "index.local.json"

ITERATIONS = 150_000     # столько же выводит ключ сайт
SLOT = 512               # длина записи после набивки: размер не должен ничего выдавать
BATCH = 16               # число фрагментов округляется вверх до кратного

DATE_RE = re.compile(r"^\d{2}\.\d{2}\.\d{4}$")

# Категория дела: она же цвет полоски на карточке и в легенде сайта.
TYPES = ("Кормёжка", "Вода", "Выгул", "Дойка", "Двор", "Своё")

# Горизонт — насколько точно дело привязано ко времени. Подробности в docs/model.md.
HORIZONS = ("time", "day", "week", "month", "season")
PLACED = ("me", "auto")

# Повторяющееся дело хранится одним фрагментом с правилом, а не тридцатью
# одинаковыми записями: сдвинуть дойку на час — одна правка, а не шесть.
WEEKDAYS = {"пн": 0, "вт": 1, "ср": 2, "чт": 3, "пт": 4, "сб": 5, "вс": 6}


# ---- пароль и ключ ----------------------------------------------------------

def root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read_password(given):
    if given:
        return given
    if os.environ.get("SCHEDULE_PASSWORD"):
        return os.environ["SCHEDULE_PASSWORD"]
    env = os.path.join(root(), ".env")
    if os.path.exists(env):
        with open(env, encoding="utf-8") as f:
            for line in f:
                key, _, value = line.partition("=")
                if key.strip() == "SCHEDULE_PASSWORD":
                    return value.strip()
    return getpass.getpass("Пароль: ")


def derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    return kdf.derive(password.encode("utf-8"))


# ---- фрагменты --------------------------------------------------------------

def b64(raw):
    return base64.b64encode(raw).decode()


def unb64(text):
    return base64.b64decode(text)


def seal(key, value):
    """Шифрует запись блоком постоянной длины: длина не должна выдавать объём."""
    raw = b"" if value is None else json.dumps(value, ensure_ascii=False,
                                               separators=(",", ":")).encode("utf-8")
    if len(raw) + 2 > SLOT:
        raise SystemExit(f"запись длиннее {SLOT - 2} байт — сократите заметку")
    block = len(raw).to_bytes(2, "big") + raw + b"\0" * (SLOT - 2 - len(raw))
    iv = secrets.token_bytes(12)
    return b64(iv + AESGCM(key).encrypt(iv, block, None))


def unseal(key, fragment):
    blob = unb64(fragment)
    block = AESGCM(key).decrypt(blob[:12], blob[12:], None)
    size = int.from_bytes(block[:2], "big")
    return json.loads(block[2:2 + size]) if size else None


def seal_index(key, entries):
    """Индекс шифруется одним куском — он маленький и читается первым."""
    raw = json.dumps(entries, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    iv = secrets.token_bytes(12)
    return b64(iv + AESGCM(key).encrypt(iv, raw, None))


def unseal_index(key, blob):
    raw = unb64(blob)
    return json.loads(AESGCM(key).decrypt(raw[:12], raw[12:], None))


# ---- файлы ------------------------------------------------------------------

def load(password, local=False):
    """Отдаёт (ключ, записи, соль)."""
    index_path = os.path.join(root(), LOCAL_INDEX_FILE if local else INDEX_FILE)
    data_path = os.path.join(root(), LOCAL_DATA_FILE if local else DATA_FILE)

    if not os.path.exists(index_path):
        # Локальный слой шифруется той же солью, что боевой: ключ один, и сайт
        # читает оба файла, а не выбирает между ними.
        main_index = os.path.join(root(), INDEX_FILE)
        if local and os.path.exists(main_index):
            with open(main_index, encoding="utf-8") as f:
                salt = unb64(json.load(f)["salt"])
        else:
            salt = secrets.token_bytes(16)
        return derive_key(password, salt), [], salt

    with open(index_path, encoding="utf-8") as f:
        index_file = json.load(f)
    salt = unb64(index_file["salt"])
    key = derive_key(password, salt)
    try:
        entries = unseal_index(key, index_file["index"])
    except Exception:
        raise SystemExit("индекс этим паролем не открывается")

    with open(data_path, encoding="utf-8") as f:
        items = json.load(f)["items"]

    records = []
    for entry in entries:
        try:
            record = unseal(key, items[entry["i"]])
        except Exception:
            raise SystemExit(f"фрагмент {entry['i']} не читается — индекс разошёлся с данными")
        if record is not None:
            records.append(record)
    return key, records, salt


def save(key, salt, records, local=False):
    """Пишет оба файла разом: фрагменты и индекс к ним.

    Записи лежат в том же порядке, что и в индексе, поэтому позиция в индексе
    и есть позиция фрагмента — искать нечего.
    """
    ordered = sorted(records, key=sort_key)
    items = [seal(key, record) for record in ordered]
    while len(items) % BATCH or not items:
        items.append(seal(key, None))

    entries = [{"d": r.get("date") or (r.get("period", "").split("-")[0] if r.get("period") else ""),
                "p": r.get("time", ""),
                "h": "repeat" if r.get("repeat") else r.get("horizon", "time"),
                "i": i}
               for i, r in enumerate(ordered)]

    write_json(LOCAL_DATA_FILE if local else DATA_FILE, {"v": 1, "items": items})
    write_json(LOCAL_INDEX_FILE if local else INDEX_FILE,
               {"v": 1, "salt": b64(salt), "index": seal_index(key, entries)})


def write_json(name, value):
    with open(os.path.join(root(), name), "w", encoding="utf-8", newline="\n") as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.write("\n")


# ---- записи -----------------------------------------------------------------

def sort_key(record):
    """Ключ порядка: дата, затем время.

    У дел без даты её роль играет начало периода, а у бессрочных — пустота:
    они уходят в конец, но из файла не пропадают."""
    date = record.get("date") or (record.get("period", "").split("-")[0] if record.get("period") else "")
    day, month, year = (date.split(".") + ["", "", ""])[:3]
    time = record.get("time", "")
    hh, _, mm = time.partition(":")
    return (year, month, day, hh.zfill(2), mm)


def parse_repeat(args):
    """«вт,чт» плюс дата окончания — в правило повторения."""
    if not args.repeat:
        return None
    days = []
    for part in args.repeat.split(","):
        key = part.strip().lower()[:2]
        if key not in WEEKDAYS:
            raise SystemExit(f"день недели один из: {', '.join(WEEKDAYS)}")
        days.append(WEEKDAYS[key])
    if not args.until:
        raise SystemExit("к --repeat нужен --until: до какой даты повторять")
    if not DATE_RE.match(args.until):
        raise SystemExit("дата окончания в формате ДД.ММ.ГГГГ")
    return {"days": sorted(set(days)), "until": args.until}


def parse_moves(pairs):
    """«15.09.2026=22.09.2026» — перенос одного повторения на другую дату."""
    out = {}
    for item in pairs or []:
        src, _, dst = item.partition("=")
        if not DATE_RE.match(src.strip()) or not DATE_RE.match(dst.strip()):
            raise SystemExit("перенос задаётся как ДД.ММ.ГГГГ=ДД.ММ.ГГГГ")
        out[src.strip()] = dst.strip()
    return out


def guess_horizon(args, prev):
    """Горизонт из того, что задано: время -> день -> период -> без срока."""
    if args.horizon:
        return args.horizon
    if prev.get("horizon"):
        return prev["horizon"]
    if args.period:
        return "month" if args.horizon == "month" else "week"
    if args.time:
        return "time"
    if args.date:
        return "day"
    return "season"


def build(args, prev=None):
    """Дело: одно и то же для цели, задачи и пункта расписания — см. docs/model.md."""
    prev = prev or {}
    record = {
        "id": prev.get("id") or str(uuid.uuid4()),
        "horizon": guess_horizon(args, prev),
        "placed": args.placed or prev.get("placed", "me"),
        "parent": args.parent if args.parent is not None else prev.get("parent", ""),
        "period": args.period if args.period is not None else prev.get("period", ""),
        "date": args.date if args.date is not None else prev.get("date", ""),
        "time": args.time if args.time is not None else prev.get("time", ""),
        "duration": int(args.duration) if args.duration else prev.get("duration"),
        "subject": args.subject if args.subject is not None else prev.get("subject", ""),
        "type": args.type if args.type is not None else prev.get("type", "Своё"),
        "room": args.room if args.room is not None else prev.get("room", ""),
        "note": args.note if args.note is not None else prev.get("note", ""),
        "tags": list(args.tag) if args.tag else prev.get("tags", []),
        "repeat": parse_repeat(args) or prev.get("repeat"),
        "skip": sorted(set((prev.get("skip") or []) + list(args.skip or []))),
        "move": {**(prev.get("move") or {}), **parse_moves(args.move)},
    }
    # Обязательное зависит только от горизонта — в этом весь смысл модели.
    if not record["subject"]:
        raise SystemExit("обязателен --subject")
    horizon = record["horizon"]
    if horizon not in HORIZONS:
        raise SystemExit(f"горизонт один из: {', '.join(HORIZONS)}")
    if record["placed"] not in PLACED:
        raise SystemExit(f"placed один из: {', '.join(PLACED)}")
    if horizon in ("time", "day"):
        if not record["date"]:
            raise SystemExit(f"при горизонте {horizon} нужна --date")
        if record["repeat"] and record["repeat"]["until"] < record["date"]:
            raise SystemExit("дата окончания повторов раньше первой даты")
        if not DATE_RE.match(record["date"]):
            raise SystemExit("дата в формате ДД.ММ.ГГГГ")
    if horizon == "time" and not record["time"]:
        raise SystemExit("при горизонте time нужно --time")
    if horizon in ("week", "month") and not record["period"]:
        raise SystemExit(f"при горизонте {horizon} нужен --period, например 03.09.2026-08.09.2026")
    if record["type"] not in TYPES:
        raise SystemExit(f"тип один из: {', '.join(TYPES)}")
    return record


def show(records):
    if not records:
        print("пусто")
        return
    for record in records:
        horizon = record.get("horizon", "time")
        if horizon in ("week", "month"):
            when = f"{'неделя' if horizon == 'week' else 'месяц'} {record.get('period', '')}"
        elif horizon == "season":
            when = "без срока"
        elif horizon == "day":
            when = "в течение дня"
        else:
            when = record.get("time") or "--:--"
            if record.get("duration"):
                when += f" +{record['duration']}м"
        who = ""
        where = f"  {record['room']}" if record.get("room") else ""
        rep = record.get("repeat")
        if rep:
            names = [k for k, v in sorted(WEEKDAYS.items(), key=lambda kv: kv[1]) if v in rep["days"]]
            when += f"  ↻ {','.join(names)} до {rep['until']}"
            if record.get("skip"):
                when += f", кроме {', '.join(record['skip'])}"
            if record.get("move"):
                when += ", перенос " + ", ".join(f"{a}→{b}" for a, b in record["move"].items())
        auto = " ~" if record.get("placed") == "auto" else "  "
        print(f"{record.get('date') or '..........'}{auto}{when}  {record['subject']}"
              f"  [{record.get('type', '')}]{who}{where}  ({record['id'][:8]})")
        if record.get("tags"):
            print("      " + " ".join("#" + t for t in record["tags"]))
        if record.get("note"):
            print(f"      {record['note']}")


# Поля записи со значениями по умолчанию: import отдаёт их в build() тем же
# набором, что и разбор командной строки, поэтому расходиться им негде.
BLANK = {"subject": None, "date": None, "time": None, "duration": None, "type": None,
         "room": None, "note": None, "tag": None, "horizon": None, "period": None,
         "placed": None, "parent": None, "repeat": None, "until": None,
         "skip": None, "move": None}


def find(records, ident):
    hits = [r for r in records if r["id"] == ident or r["id"].startswith(ident)]
    if not hits:
        raise SystemExit(f"запись {ident} не найдена")
    if len(hits) > 1:
        raise SystemExit(f"под {ident} подходит несколько записей — уточните id")
    return hits[0]


# ---- команды ----------------------------------------------------------------

def main():
    # Консоль Windows не в utf-8, и расшифрованное вышло бы кракозябрами.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description="Хозяйство: записи и индекс")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def fields(p):
        p.add_argument("--subject", help="что за дело")
        p.add_argument("--date", help="ДД.ММ.ГГГГ")
        p.add_argument("--time", help="ЧЧ:ММ, начало дела")
        p.add_argument("--duration", help="сколько минут займёт — нужно, чтобы видеть наложения")
        p.add_argument("--type", choices=TYPES, help="категория: " + ", ".join(TYPES))
        p.add_argument("--room", help="где: баня, пристройка, вольер 1")
        p.add_argument("--note")
        p.add_argument("--tag", action="append",
                       help="метка по смыслу: двор, спросить-маму. Можно несколько")
        p.add_argument("--horizon", choices=HORIZONS,
                       help="точность: time, day, week, month, season. Обычно понятен сам")
        p.add_argument("--period", help="границы для week и month: ДД.ММ.ГГГГ-ДД.ММ.ГГГГ")
        p.add_argument("--placed", choices=PLACED,
                       help="me — время выбрано владельцем, auto — предложено ассистентом")
        p.add_argument("--parent", help="id дела, из которого это выросло")
        p.add_argument("--repeat", help="дни недели через запятую: пн,вт,ср,чт,пт,сб,вс")
        p.add_argument("--until", help="до какой даты повторять, ДД.ММ.ГГГГ")
        p.add_argument("--skip", action="append", help="отменить одно повторение: ДД.ММ.ГГГГ")
        p.add_argument("--move", action="append",
                       help="перенести одно повторение: ДД.ММ.ГГГГ=ДД.ММ.ГГГГ")

    for name, help_text in (("list", "показать записи"), ("add", "добавить"),
                            ("edit", "изменить"), ("rm", "удалить"),
                            ("import", "залить распорядок из json-файла"),
                            ("replan", "убрать всё, что расставлено автоматически")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--password", help="иначе SCHEDULE_PASSWORD, .env или спросим")
        p.add_argument("--local", action="store_true",
                       help="локальный слой: видно только на своей машине, в git не уедет")
        if name in ("list", "replan"):
            p.add_argument("--from", dest="date_from", help="с этой даты")
            p.add_argument("--to", dest="date_to", help="по эту дату")
        if name == "list":
            p.add_argument("--filter-tag", dest="filter_tag", help="только записи с этой меткой")
        if name in ("edit", "rm"):
            p.add_argument("--id", required=True)
        if name == "import":
            p.add_argument("--file", required=True,
                           help="json-список записей теми же полями, что у add")
            p.add_argument("--replace", action="store_true",
                           help="заменить всё, что было, а не дописать")
        if name in ("add", "edit"):
            fields(p)

    args = parser.parse_args()
    key, records, salt = load(read_password(args.password), args.local)

    if args.cmd == "list":
        chosen = records
        # Границы сравниваем по дате, а не по полному ключу: иначе запись без
        # номера пары оказывается «позже» верхней границы того же дня.
        def day_key(text):
            day, month, year = (text.split(".") + ["", "", ""])[:3]
            return (year, month, day)

        if args.date_from:
            chosen = [r for r in chosen if day_key(r.get("date", "")) >= day_key(args.date_from)]
        if args.date_to:
            chosen = [r for r in chosen if day_key(r.get("date", "")) <= day_key(args.date_to)]
        if getattr(args, "filter_tag", None):
            chosen = [r for r in chosen if args.filter_tag in (r.get("tags") or [])]
        show(chosen)
        return

    if args.cmd == "import":
        # Распорядок дня — три десятка дел, и заводить их по одному значит
        # тридцать раз перевыпустить оба файла. Файл заливается разом.
        with open(args.file, encoding="utf-8") as f:
            raw = json.load(f)
        if not isinstance(raw, list):
            raise SystemExit("в файле ожидается список записей")
        fresh = [build(argparse.Namespace(**{**BLANK, **item})) for item in raw]
        save(key, salt, (
            [] if args.replace else records) + fresh, args.local)
        print(f"залито записей: {len(fresh)}"
              + ("" if args.replace else f", всего стало {len(records) + len(fresh)}"))
        return

    if args.cmd == "add":
        record = build(args)
        save(key, salt, records + [record], args.local)
        print(f"добавлена {record['id'][:8]} — {record['subject']}")
        return

    if args.cmd == "edit":
        prev = find(records, args.id)
        record = build(args, prev)
        records[records.index(prev)] = record
        save(key, salt, records, args.local)
        print(f"изменена {record['id'][:8]} — {record['subject']}")
        return

    if args.cmd == "replan":
        # Своё время владельца неприкосновенно: убираем только предложенное.
        def day_key(text):
            day, month, year = (text.split(".") + ["", "", ""])[:3]
            return (year, month, day)

        doomed = [r for r in records if r.get("placed") == "auto"]
        if args.date_from:
            doomed = [r for r in doomed if day_key(r.get("date", "")) >= day_key(args.date_from)]
        if args.date_to:
            doomed = [r for r in doomed if day_key(r.get("date", "")) <= day_key(args.date_to)]
        if not doomed:
            print("нечего пересобирать: автоматически расставленного нет")
            return
        left = [r for r in records if r not in doomed]
        save(key, salt, left, args.local)
        print(f"убрано автоматически расставленных: {len(doomed)}")
        for r in doomed:
            print(f"  {r.get('date') or '..........'}  {r['subject']}")
        return

    if args.cmd == "rm":
        record = find(records, args.id)
        records.remove(record)
        save(key, salt, records, args.local)
        print(f"удалена {record['id'][:8]} — {record['subject']}")
        return


if __name__ == "__main__":
    sys.exit(main())
