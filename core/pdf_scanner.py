"""Deterministic PDF inspection used before untrusted document analysis."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from pypdf import PdfReader
except ImportError:  # pragma: no cover - setup installs the dependency
    PdfReader = None  # type: ignore[assignment,misc]


@dataclass(frozen=True)
class PdfInspection:
    path: str
    sha256: str
    page_count: int
    extracted_text: str
    indicators: tuple[str, ...]

    @property
    def safe(self) -> bool:
        return not self.indicators

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "page_count": self.page_count,
            "text_length": len(self.extracted_text),
            "indicators": list(self.indicators),
            "safe": self.safe,
        }


_PATTERNS: tuple[tuple[str, str], ...] = (
    ("prompt_injection", r"ignore\s+(all\s+)?previous\s+instructions"),
    ("prompt_injection", r"disregard\s+(the\s+)?original\s+(task|request|instructions)"),
    ("prompt_injection", r"do\s+not\s+tell\s+the\s+user"),
    ("sensitive_data", r"student\s+(records?|database)"),
    ("external_transfer", r"(email|send|upload|export).*external"),
)


def inspect_pdf(path: str | Path, *, max_text_chars: int = 100_000) -> PdfInspection:
    """Read a real PDF, hash the bytes, and return bounded extracted evidence."""
    pdf_path = Path(path)
    if not pdf_path.is_file():
        raise FileNotFoundError(f"PDF does not exist: {pdf_path}")
    raw = pdf_path.read_bytes()
    if not raw.startswith(b"%PDF-"):
        raise ValueError(f"not a PDF file: {pdf_path}")
    if PdfReader is None:
        raise RuntimeError("pypdf is required for PDF inspection")
    try:
        reader = PdfReader(str(pdf_path), strict=False)
        text = "\n".join(page.extract_text() or "" for page in reader.pages)
        pages = len(reader.pages)
    except Exception as exc:
        raise ValueError(f"could not parse PDF {pdf_path}: {exc}") from exc
    text = text[:max_text_chars]
    indicators = tuple(
        sorted({name for name, pattern in _PATTERNS if re.search(pattern, text, re.IGNORECASE)})
    )
    return PdfInspection(
        path=str(pdf_path),
        sha256=hashlib.sha256(raw).hexdigest(),
        page_count=pages,
        extracted_text=text,
        indicators=indicators,
    )


__all__ = ["PdfInspection", "inspect_pdf"]
