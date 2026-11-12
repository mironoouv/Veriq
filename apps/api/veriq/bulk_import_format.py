"""Bounded CSV and XLSX readers for the onboarding preview."""

import csv
import io
import re
import zlib
from dataclasses import dataclass
from time import monotonic
from xml.etree import ElementTree
from zipfile import ZIP_DEFLATED, ZIP_STORED, BadZipFile, ZipFile

from veriq.registration_policy import canonical_email

MAX_UPLOAD = 256 * 1024
MAX_XML = 2 * 1024 * 1024
MAX_ROWS = 500
MAX_COLUMNS = 32
_NAMESPACE = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_CELL = re.compile(r"([A-Z]{1,2})([1-9][0-9]{0,3})")


class ImportFormatError(ValueError):
    """Invalid workbook or exhausted parsing budget."""


@dataclass(frozen=True)
class PreviewRow:
    number: int
    email: str | None
    error: str | None


def _budget(deadline: float) -> None:
    if monotonic() >= deadline:
        raise ImportFormatError("time_limit")


def _xml(payload: bytes) -> ElementTree.Element:
    try:
        source = payload.decode("utf-8-sig")
        if "<!" in source:
            raise ImportFormatError("unsupported_xml_declaration")
        return ElementTree.fromstring(source)
    except (UnicodeError, ElementTree.ParseError):
        raise ImportFormatError("invalid_xml") from None


def _text(element: ElementTree.Element) -> str:
    return "".join(node.text or "" for node in element.iter(_NAMESPACE + "t"))


def _xlsx(payload: bytes, deadline: float) -> list[tuple[int, list[str]]]:
    with ZipFile(io.BytesIO(payload)) as archive:
        entries = archive.infolist()
        if len(entries) > 32 or sum(info.file_size for info in entries) > MAX_XML:
            raise ImportFormatError("xlsx_resource_limit")
        names = {info.filename for info in entries}
        if len(names) != len(entries) or any(
            info.compress_type not in {ZIP_DEFLATED, ZIP_STORED}
            or info.flag_bits & 1
            or info.filename.startswith("/")
            or ".." in info.filename.split("/")
            or "\\" in info.filename
            or "vbaproject" in info.filename.lower()
            or "externallinks/" in info.filename.lower()
            for info in entries
        ):
            raise ImportFormatError("unsupported_workbook_part")
        sheets = {
            name
            for name in names
            if name.startswith("xl/worksheets/") and name.endswith(".xml")
        }
        if sheets != {"xl/worksheets/sheet1.xml"} or "xl/workbook.xml" not in names:
            raise ImportFormatError("one_worksheet_required")
        workbook = _xml(archive.read("xl/workbook.xml"))
        workbook_sheets = list(workbook.iter(_NAMESPACE + "sheet"))
        if len(workbook_sheets) != 1:
            raise ImportFormatError("one_worksheet_required")
        sheet_id = workbook_sheets[0].get(f"{{{_REL}}}id")
        matching_targets: list[str | None] = []
        for name in names:
            _budget(deadline)
            if name.endswith(".rels"):
                rels = _xml(archive.read(name))
                if any(
                    child.get("TargetMode", "").lower() == "external" for child in rels
                ):
                    raise ImportFormatError("external_relationship")
                if name == "xl/_rels/workbook.xml.rels" and sheet_id:
                    matching_targets.extend(
                        child.get("Target")
                        for child in rels
                        if child.get("Id") == sheet_id
                        and child.get("Type") == f"{_REL}/worksheet"
                    )
        if matching_targets not in (
            ["worksheets/sheet1.xml"],
            ["/xl/worksheets/sheet1.xml"],
        ):
            raise ImportFormatError("invalid_worksheet_relationship")
        shared = (
            [_text(item) for item in _xml(archive.read("xl/sharedStrings.xml"))]
            if "xl/sharedStrings.xml" in names
            else []
        )
        if len(shared) > (MAX_ROWS + 1) * MAX_COLUMNS:
            raise ImportFormatError("xlsx_resource_limit")
        sheet = _xml(archive.read("xl/worksheets/sheet1.xml"))
        data = sheet.find(_NAMESPACE + "sheetData")
        if data is None:
            raise ImportFormatError("missing_worksheet_data")
        rows: list[tuple[int, list[str]]] = []
        for row in data:
            _budget(deadline)
            if row.tag != _NAMESPACE + "row" or len(rows) >= MAX_ROWS + 1:
                raise ImportFormatError("row_limit")
            raw_number = row.get("r", "")
            if not re.fullmatch(r"[1-9][0-9]{0,3}", raw_number):
                raise ImportFormatError("invalid_row_reference")
            number = int(raw_number)
            if rows and number <= rows[-1][0]:
                raise ImportFormatError("invalid_row_order")
            values: dict[int, str] = {}
            for cell in row:
                reference = _CELL.fullmatch(cell.get("r", ""))
                if reference is None or int(reference[2]) != number:
                    raise ImportFormatError("invalid_cell_reference")
                column = 0
                for letter in reference[1]:
                    column = column * 26 + ord(letter) - ord("A") + 1
                if column > MAX_COLUMNS or column in values:
                    raise ImportFormatError("column_limit_or_duplicate")
                if cell.find(_NAMESPACE + "f") is not None:
                    raise ImportFormatError("formula_cells")
                kind = cell.get("t")
                value = cell.findtext(_NAMESPACE + "v", "")
                if kind == "s":
                    if not re.fullmatch(r"[0-9]{1,5}", value) or int(value) >= len(
                        shared
                    ):
                        raise ImportFormatError("invalid_shared_string")
                    value = shared[int(value)]
                elif kind == "inlineStr":
                    value = _text(cell)
                values[column] = value
            rows.append(
                (
                    number,
                    [values.get(i, "") for i in range(1, max(values, default=0) + 1)],
                )
            )
        return rows


def _csv(payload: bytes, deadline: float) -> list[tuple[int, list[str]]]:
    source = io.StringIO(payload.decode("utf-8-sig"), newline="")
    reader = csv.reader(source, strict=True)
    rows: list[tuple[int, list[str]]] = []
    while True:
        _budget(deadline)
        number = reader.line_num + 1
        values = next(reader, None)
        if values is None:
            return rows
        if len(rows) >= MAX_ROWS + 1 or len(values) > MAX_COLUMNS:
            raise ImportFormatError("row_or_column_limit")
        rows.append((number, values))


def preview(
    payload: bytes, file_format: str, email_column: str = "email"
) -> list[PreviewRow]:
    if not 0 < len(payload) <= MAX_UPLOAD:
        raise ImportFormatError("file_size")
    deadline = monotonic() + 2
    try:
        if file_format == "csv":
            rows = _csv(payload, deadline)
        elif file_format == "xlsx":
            rows = _xlsx(payload, deadline)
        else:
            raise ImportFormatError("unsupported_format")
    except (
        BadZipFile,
        UnicodeError,
        csv.Error,
        KeyError,
        NotImplementedError,
        RuntimeError,
        OSError,
        zlib.error,
    ):
        raise ImportFormatError("invalid_file") from None
    if not rows or len(rows) == 1:
        raise ImportFormatError("missing_data")
    headers = [value.strip().casefold() for value in rows[0][1]]
    column_name = email_column.strip().casefold()
    if not column_name or headers.count(column_name) != 1:
        raise ImportFormatError("missing_or_duplicate_email_column")
    column = headers.index(column_name)
    seen: set[str] = set()
    result = []
    for number, values in rows[1:]:
        _budget(deadline)
        try:
            if len(values) > len(headers):
                result.append(PreviewRow(number, None, "unexpected_columns"))
                continue
            email = canonical_email(values[column] if column < len(values) else "")
        except ValueError:
            result.append(PreviewRow(number, None, "invalid_email"))
            continue
        if email in seen:
            result.append(PreviewRow(number, None, "duplicate_in_file"))
        else:
            seen.add(email)
            result.append(PreviewRow(number, email, None))
    return result
