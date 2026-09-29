# Extracting emails, credit cards, URLs and HTML tags from messy text.

import re
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent #referring to our base dir
MAX_INPUT_BYTES = 200_000  # dont process huge files. lets just work with small text

# Patterns use fixed limits like {1,64} so hostile input can't make them hang (ReDoS)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b")
BAD_EMAIL_PATTERN = re.compile(r"\.\.|^\.|\.@|@[.-]")  # double dots, dots at the edges

# One pattern per ALU email type; each needs different text after the "@"
username = r"[A-Za-z0-9._%+-]{1,64}@"
ALU_PATTERNS = {
    "alu_official": re.compile(username + r"alueducation\.com", re.I),
    "alu_alumni": re.compile(username + r"alumni\.alueducation\.com", re.I),
    "alu_si": re.compile(username + r"si\.alueducation\.com", re.I),
}

CARD_PATTERN = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")  # 13-19 digits, we shall do luhn check later
CARD_TYPES = {
    "Visa": r"4\d{12}(?:\d{3}){0,2}",
    "Mastercard": r"(?:5[1-5]|2[2-7])\d{14}",
    "Equity": r"3[47]\d{13}",
    "BK": r"(?:6011\d{12}|65\d{14})",
}
# http urls only
URL_PATTERN = re.compile(r"\bhttps?://[^\s<>\"')]+", re.I)  

# HTML tag like <p>, </p>, <br/> or <a href="...">
NAME = r"[A-Za-z][A-Za-z0-9_-]{0,29}"
VALUE = r"(?:\"[^\"<>]{0,300}\"|'[^'<>]{0,300}'|[^\s\"'<>=`]{1,100})"
HTML_TAG_PATTERN = re.compile(
    r"</?[A-Za-z][A-Za-z0-9]{0,9}(?:\s{1,20}" + NAME + r"(?:\s{0,20}=\s{0,20}" + VALUE + r")?){0,10}\s{0,20}/?>"
)
# Only these tags and attributes count as safe (no <form>, <meta>, style=, etc.)
SAFE_HTML_TAGS = {"a", "b", "i", "p", "br", "hr", "div", "span", "strong", "em",
                  "ul", "ol", "li", "img", "h1", "h2", "h3", "table", "tr", "td", "th"}
SAFE_HTML_ATTRIBUTES = {"href", "src", "alt", "title", "class", "id", "width", "height"}

# Any line matching one of these is dropped before extraction and logged
HIDDEN_CHARS = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
SUSPICIOUS_PATTERNS = [
    ("xss_attempt", re.compile(
        r"<\s*(script|iframe|object|embed)\b|javascript\s*:|\bon(?:error|load|click|focus)\s*=", re.I)),
    # the last part is an isolated "--", so lines of dashes are fine
    ("sql_injection", re.compile(
        r"'\s*OR\s+'?\d+'?\s*=\s*'?\d+|;\s*DROP\s+TABLE|UNION\s+SELECT|(?<!-)--(?!-)\s*$", re.I)),
    ("prompt_injection", re.compile(r"\bignore\s+(all\s+)?previous\s+instructions\b|\bsystem\s+prompt\b", re.I)),
    ("hidden_characters", HIDDEN_CHARS),  # can be used to fake a file extension
]

# functions that will help us
def remove_unsafe_lines(raw_text):
    """Drops every suspicious line and logs why."""
    clean, log = [], []
    for number, line in enumerate(raw_text.splitlines(), start=1):
        reasons = [name for name, pattern in SUSPICIOUS_PATTERNS if pattern.search(line)]
        if reasons:
            snippet = HIDDEN_CHARS.sub("", line).strip()[:40]  # keeps the log safe to read
            log.append({"line_number": number, "categories": reasons, "snippet": snippet})
        else:
            clean.append(line)
    return "\n".join(clean), log


def hide_email(email):
    """al***@alueducation.com"""
    name, domain = email.split("@", 1)
    keep = 2 if len(name) > 2 else 1
    return name[:keep] + "*" * max(len(name) - keep, 1) + "@" + domain


def hide_card(digits):
    """**** **** **** 1111 (only the last 4 digits are shown)"""
    stars = "*" * (len(digits) - 4)
    return " ".join([stars[i:i + 4] for i in range(0, len(stars), 4)] + [digits[-4:]])


def passes_luhn(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch) * (2 if i % 2 else 1)
        total += n - 9 if n > 9 else n
    return total % 10 == 0


def html_tag_is_safe(tag):
    name = re.match(r"</?([A-Za-z0-9]+)", tag).group(1).lower()
    attributes = {a.lower() for a in re.findall(r"\s([A-Za-z][A-Za-z0-9_-]*)\s*=", tag)}
    return name in SAFE_HTML_TAGS and attributes <= SAFE_HTML_ATTRIBUTES


def blank(pattern, text):
    """Replaces matches with spaces so later patterns don't match them again."""
    return pattern.sub(lambda m: " " * len(m.group(0)), text)


def extract_html_tags(text):
    valid, unsafe = [], []

    def check(match):
        tag = match.group(0)
        if html_tag_is_safe(tag):
            valid.append(re.sub(r"\s+", " ", tag))
            return tag
        unsafe.append(tag)
        return " " * len(tag)  # blanked, so a URL inside an unsafe tag is ignored too

    text = HTML_TAG_PATTERN.sub(check, text)
    return valid, len(unsafe), text


def extract_urls(text):
    urls = [m.group(0).rstrip(".,;:!?") for m in URL_PATTERN.finditer(text)]
    return urls, blank(URL_PATTERN, text)


def extract_emails(text):
    found = {"alu_official": [], "alu_alumni": [], "alu_si": [], "general": []}
    malformed = 0
    for m in EMAIL_PATTERN.finditer(text):
        email = m.group(0)
        if BAD_EMAIL_PATTERN.search(email):
            malformed += 1
            continue
        kind = next((k for k, p in ALU_PATTERNS.items() if p.fullmatch(email)), "general")
        found[kind].append(hide_email(email))
    return found, malformed, blank(EMAIL_PATTERN, text)


def extract_credit_cards(text):
    valid, rejected = [], []
    for m in CARD_PATTERN.finditer(text):
        digits = re.sub(r"[ -]", "", m.group(0))
        if passes_luhn(digits):
            kind = next((k for k, p in CARD_TYPES.items() if re.fullmatch(p, digits)), "Unknown")
            valid.append({"type": kind, "masked": hide_card(digits)})
        else:
            rejected.append({"masked": hide_card(digits), "reason": "failed_luhn_check"})
    return valid, rejected, blank(CARD_PATTERN, text)


def analyze(raw_text):
    text, log = remove_unsafe_lines(raw_text)
    # HTML goes first so unsafe tags are blanked before we look for URLs
    tags, unsafe_tags, text = extract_html_tags(text)
    urls, text = extract_urls(text)
    emails, malformed_emails, text = extract_emails(text)
    valid_cards, rejected_cards, text = extract_credit_cards(text)
    return {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "input_lines": len(raw_text.splitlines()),
        },
        "results": {
            "emails": emails,
            "credit_cards": {"valid": valid_cards, "rejected": rejected_cards},
            "urls": urls,
            "html_tags": tags,
        },
        "rejected_counts": {"malformed_emails": malformed_emails, "unsafe_html_tags": unsafe_tags},
        "security": {
            "flagged_lines": log,
            "total_flagged": len(log),
            "note": "Flagged lines are excluded entirely, so nothing on them is reported above.",
        },
    }


def print_summary(report):
    r = report["results"]
    print("Emails:", {kind: len(items) for kind, items in r["emails"].items()})
    print("Credit cards:", {kind: len(items) for kind, items in r["credit_cards"].items()})
    print("URLs:", len(r["urls"]))
    print("HTML tags:", len(r["html_tags"]), "safe,", report["rejected_counts"]["unsafe_html_tags"], "unsafe")
    for entry in report["security"]["flagged_lines"]:
        print(f"Skipped line {entry['line_number']}: {', '.join(entry['categories'])}")


def main():
    in_path = Path(sys.argv[1]) if len(sys.argv) > 1 else BASE_DIR / "input" / "raw-text.txt"
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else BASE_DIR / "output" / "sample-output.json"
    raw_text = in_path.read_bytes()[:MAX_INPUT_BYTES].decode("utf-8", errors="replace")
    report = analyze(raw_text)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print_summary(report)
    print(f"Full report saved to: {out_path}")


if __name__ == "__main__":
    main()
