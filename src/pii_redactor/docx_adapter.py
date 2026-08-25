from collections.abc import Callable
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from lxml import etree
from PIL import Image, ImageDraw

from pii_redactor.domain import PseudonymizedText, TextReplacement


WORD_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
DRAWING_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"
CUSTOM_PROPERTIES_REL = "/custom-properties"
SAFE_EXTERNAL_TARGET = "https://example.invalid/"
CUSTOM_PROPERTY_PARTS = {
    "docProps/custom.xml",
    "docProps/_rels/custom.xml.rels",
}
TEXT_TAGS_BY_PARAGRAPH = {
    f"{{{WORD_NS}}}p": {
        f"{{{WORD_NS}}}t",
        f"{{{WORD_NS}}}delText",
        f"{{{WORD_NS}}}instrText",
    },
    f"{{{DRAWING_NS}}}p": {f"{{{DRAWING_NS}}}t"},
}
TEXT_ATTRIBUTE_NAMES = {"descr", "title", "instr"}
PRIVATE_ATTRIBUTE_NAMES = {"author", "initials"}
CORE_PROPERTIES_TO_CLEAR = {"creator", "lastModifiedBy"}
APP_PROPERTIES_TO_CLEAR = {"Company", "HyperlinkBase", "Manager"}
XML_PARSER = etree.XMLParser(
    load_dtd=False,
    no_network=True,
    recover=False,
    resolve_entities=False,
)


class DocxRedactor:
    """Redacts and sanitizes a DOCX by editing its OOXML package."""

    def __init__(self) -> None:
        self._image_sanitizer = NeutralImageSanitizer()

    def redact(
        self,
        source_path: Path,
        output_path: Path,
        transform: Callable[[str], PseudonymizedText],
    ) -> None:
        source_path = Path(source_path)
        output_path = Path(output_path)
        if source_path.resolve() == output_path.resolve():
            raise ValueError("Input and output paths must be different")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with ZipFile(source_path) as source, ZipFile(
            output_path, "w", ZIP_DEFLATED
        ) as output:
            for info in source.infolist():
                if info.filename in CUSTOM_PROPERTY_PARTS:
                    continue
                data = self._sanitize_part(
                    info.filename, source.read(info.filename), transform
                )
                output.writestr(_copied_zip_info(info), data)

    def _sanitize_part(
        self,
        name: str,
        data: bytes,
        transform: Callable[[str], PseudonymizedText],
    ) -> bytes:
        if name.startswith("word/media/") and not name.endswith("/"):
            return self._image_sanitizer.sanitize(data, name)
        if name.endswith(".rels"):
            return _sanitize_relationships(data)
        if name == "[Content_Types].xml":
            return _remove_custom_property_content_type(data)
        if not name.endswith(".xml"):
            return data

        root = _parse_xml(data)
        _scrub_private_attributes(root)
        if name == "docProps/core.xml":
            _clear_elements(root, CORE_PROPERTIES_TO_CLEAR)
        elif name == "docProps/app.xml":
            _clear_elements(root, APP_PROPERTIES_TO_CLEAR)
        _redact_text(root, transform)
        return etree.tostring(
            root, xml_declaration=True, encoding="UTF-8", standalone=True
        )


class NeutralImageSanitizer:
    """Replaces raster media with deterministic, metadata-free placeholders."""

    def sanitize(self, data: bytes, part_name: str) -> bytes:
        try:
            with Image.open(BytesIO(data)) as source:
                image_format = source.format
                size = source.size
        except Exception as error:
            raise ValueError(f"Unsupported embedded image: {part_name}") from error
        if image_format not in {"JPEG", "PNG"}:
            raise ValueError(
                f"Unsupported embedded image format {image_format}: {part_name}"
            )

        placeholder = Image.new("RGB", size, (229, 231, 235))
        drawing = ImageDraw.Draw(placeholder)
        if size[0] > 1 and size[1] > 1:
            drawing.rectangle(
                (0, 0, size[0] - 1, size[1] - 1), outline=(107, 114, 128)
            )
            drawing.line(
                (0, 0, size[0] - 1, size[1] - 1), fill=(156, 163, 175)
            )
            drawing.line(
                (0, size[1] - 1, size[0] - 1, 0), fill=(156, 163, 175)
            )

        output = BytesIO()
        save_options = {"quality": 90} if image_format == "JPEG" else {}
        placeholder.save(output, format=image_format, **save_options)
        return output.getvalue()


def _redact_text(
    root: etree._Element,
    transform: Callable[[str], PseudonymizedText],
) -> None:
    paragraph_tags = set(TEXT_TAGS_BY_PARAGRAPH)
    for paragraph_tag, text_tags in TEXT_TAGS_BY_PARAGRAPH.items():
        for paragraph in root.iter(paragraph_tag):
            nodes = tuple(
                node
                for node in paragraph.iter()
                if node.tag in text_tags
                and _nearest_paragraph(node, paragraph_tags) is paragraph
            )
            _redact_nodes(nodes, transform)

    for element in root.iter():
        for attribute_name in tuple(element.attrib):
            if etree.QName(attribute_name).localname not in TEXT_ATTRIBUTE_NAMES:
                continue
            element.attrib[attribute_name] = transform(
                element.attrib[attribute_name]
            ).text


def _nearest_paragraph(
    element: etree._Element, paragraph_tags: set[str]
) -> etree._Element | None:
    return next(
        (
            ancestor
            for ancestor in element.iterancestors()
            if ancestor.tag in paragraph_tags
        ),
        None,
    )


def _redact_nodes(
    nodes: tuple[etree._Element, ...],
    transform: Callable[[str], PseudonymizedText],
) -> None:
    if not nodes:
        return
    original = "".join(node.text or "" for node in nodes)
    transformed = transform(original)
    for replacement in sorted(
        transformed.replacements, key=lambda item: item.start, reverse=True
    ):
        _replace_span(nodes, replacement)
    actual = "".join(node.text or "" for node in nodes)
    if actual != transformed.text:
        raise ValueError("DOCX patch does not match pseudonymizer output")


def _replace_span(
    nodes: tuple[etree._Element, ...], replacement: TextReplacement
) -> None:
    boundaries: list[tuple[int, int]] = []
    cursor = 0
    for node in nodes:
        text = node.text or ""
        boundaries.append((cursor, cursor + len(text)))
        cursor += len(text)

    affected = [
        index
        for index, (start, end) in enumerate(boundaries)
        if replacement.start < end and replacement.end > start
    ]
    if not affected:
        raise ValueError("Replacement span does not intersect a DOCX text node")

    first_index = affected[0]
    last_index = affected[-1]
    first_start, _ = boundaries[first_index]
    last_start, _ = boundaries[last_index]
    prefix = (nodes[first_index].text or "")[
        : replacement.start - first_start
    ]
    suffix = (nodes[last_index].text or "")[replacement.end - last_start :]

    if first_index == last_index:
        _set_text(nodes[first_index], prefix + replacement.value + suffix)
        return
    _set_text(nodes[first_index], prefix + replacement.value)
    for index in affected[1:-1]:
        _set_text(nodes[index], "")
    _set_text(nodes[last_index], suffix)


def _set_text(element: etree._Element, value: str) -> None:
    element.text = value
    xml_space = "{http://www.w3.org/XML/1998/namespace}space"
    if value[:1].isspace() or value[-1:].isspace():
        element.set(xml_space, "preserve")
    else:
        element.attrib.pop(xml_space, None)


def _scrub_private_attributes(root: etree._Element) -> None:
    for element in root.iter():
        for attribute_name in tuple(element.attrib):
            local_name = etree.QName(attribute_name).localname
            if local_name.startswith("rsid"):
                del element.attrib[attribute_name]
            elif local_name in PRIVATE_ATTRIBUTE_NAMES:
                element.attrib[attribute_name] = ""


def _clear_elements(root: etree._Element, local_names: set[str]) -> None:
    for element in root.iter():
        if etree.QName(element).localname in local_names:
            element.text = ""


def _sanitize_relationships(data: bytes) -> bytes:
    root = _parse_xml(data)
    for relationship in tuple(root):
        relationship_type = relationship.get("Type", "")
        target = relationship.get("Target", "")
        if relationship_type.endswith(CUSTOM_PROPERTIES_REL) or target.lstrip(
            "/"
        ) == "docProps/custom.xml":
            root.remove(relationship)
        elif relationship.get("TargetMode") == "External":
            relationship.set("Target", SAFE_EXTERNAL_TARGET)
    return etree.tostring(
        root, xml_declaration=True, encoding="UTF-8", standalone=True
    )


def _remove_custom_property_content_type(data: bytes) -> bytes:
    root = _parse_xml(data)
    for item in tuple(root):
        if item.get("PartName") == "/docProps/custom.xml":
            root.remove(item)
    return etree.tostring(
        root, xml_declaration=True, encoding="UTF-8", standalone=True
    )


def _parse_xml(data: bytes) -> etree._Element:
    return etree.fromstring(data, parser=XML_PARSER.copy())


def _copied_zip_info(info: ZipInfo) -> ZipInfo:
    copied = ZipInfo(info.filename, date_time=info.date_time)
    copied.compress_type = info.compress_type
    copied.comment = info.comment
    copied.extra = info.extra
    copied.create_system = info.create_system
    copied.create_version = info.create_version
    copied.extract_version = info.extract_version
    copied.flag_bits = info.flag_bits
    copied.internal_attr = info.internal_attr
    copied.external_attr = info.external_attr
    return copied
