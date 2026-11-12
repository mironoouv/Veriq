from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from veriq.bulk_import_format import MAX_ROWS, MAX_UPLOAD, ImportFormatError, preview


def workbook(cell: str, relationship: str = "") -> bytes:
    output = BytesIO()
    ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr(
            "xl/workbook.xml",
            f'<workbook xmlns="{ns}" xmlns:r="{rel}"><sheets><sheet r:id="rId1"/></sheets></workbook>',
        )
        archive.writestr(
            "xl/worksheets/sheet1.xml",
            f'<worksheet xmlns="{ns}"><sheetData>'
            '<row r="1"><c r="A1" t="inlineStr"><is><t>Email</t></is></c></row>'
            f'<row r="2">{cell}</row></sheetData></worksheet>',
        )
        archive.writestr(
            "xl/_rels/workbook.xml.rels",
            relationship
            or f'<Relationships><Relationship Id="rId1" Type="{rel}/worksheet" '
            'Target="worksheets/sheet1.xml"/></Relationships>',
        )
    return output.getvalue()


def test_csv_mapping_deduplication_and_formula_text() -> None:
    rows = preview(
        b'Name,Mail\nStudent, Test@Example.Invalid \nDuplicate,test@example.invalid\n"=1+2",invalid\n',
        "csv",
        "Mail",
    )
    assert [row.email for row in rows] == ["test@example.invalid", None, None]
    assert [row.error for row in rows] == [None, "duplicate_in_file", "invalid_email"]


def test_xlsx_text_and_reject_active_content() -> None:
    cell = '<c r="A2" t="inlineStr"><is><t>Test@Example.Invalid</t></is></c>'
    assert preview(workbook(cell), "xlsx")[0].email == "test@example.invalid"
    with pytest.raises(ImportFormatError, match="formula"):
        preview(workbook('<c r="A2"><f>2+2</f><v>4</v></c>'), "xlsx")
    with pytest.raises(ImportFormatError, match="external"):
        preview(
            workbook(
                cell,
                '<Relationships><Relationship TargetMode="External"/></Relationships>',
            ),
            "xlsx",
        )


@pytest.mark.parametrize(
    ("content", "kind"),
    [
        (b"email\n\xff", "csv"),
        (b"invalid zip", "xlsx"),
        (b"email\n" + b"a@example.invalid\n" * (MAX_ROWS + 1), "csv"),
        (b"x" * (MAX_UPLOAD + 1), "csv"),
        (b"email,email\na,b", "csv"),
    ],
)
def test_import_limits_and_invalid_documents(content: bytes, kind: str) -> None:
    with pytest.raises(ImportFormatError):
        preview(content, kind)
