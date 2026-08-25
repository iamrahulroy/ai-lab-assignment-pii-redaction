import hashlib
import re
import zipfile
from io import BytesIO
from pathlib import Path

from docx import Document
from lxml import etree
from PIL import Image

from pii_redactor.domain import MappingDocument, ValidationResult


class DocxValidationSuite:
    def validate(
        self,
        source_path: Path,
        output_path: Path,
        mapping: MappingDocument,
    ) -> ValidationResult:
        self._validate_hashes(source_path, output_path, mapping)
        self._validate_package(output_path)
        self._validate_originals_absent(output_path, mapping)
        image_count = self._validate_images(source_path, output_path)
        warnings = (
            ("embedded_images_replaced_without_ocr",) if image_count else ()
        )
        return ValidationResult(
            warnings=warnings + ("visual_render_required_before_delivery",)
        )

    @staticmethod
    def _validate_hashes(
        source_path: Path, output_path: Path, mapping: MappingDocument
    ) -> None:
        metadata = mapping.metadata
        if _sha256(source_path) != metadata.source_sha256:
            raise ValueError("Source hash changed during redaction")
        if _sha256(output_path) != metadata.output_sha256:
            raise ValueError("Output hash does not match mapping metadata")

    @staticmethod
    def _validate_package(output_path: Path) -> None:
        if not zipfile.is_zipfile(output_path):
            raise ValueError("Output is not a valid DOCX ZIP package")
        with zipfile.ZipFile(output_path) as package:
            if package.testzip() is not None:
                raise ValueError("Output DOCX contains a corrupt ZIP part")
        Document(output_path)

    @staticmethod
    def _validate_originals_absent(
        output_path: Path, mapping: MappingDocument
    ) -> None:
        originals = frozenset(
            record.original.casefold()
            for record in mapping.mappings
            if record.original
        )
        if not originals:
            return
        pattern = re.compile(
            "|".join(re.escape(value) for value in sorted(originals))
        )
        with zipfile.ZipFile(output_path) as package:
            for name in package.namelist():
                if not name.endswith((".xml", ".rels")):
                    continue
                for value in _searchable_values(package.read(name)):
                    if pattern.search(value.casefold()):
                        raise ValueError("Original PII remains in output package")

    @staticmethod
    def _validate_images(source_path: Path, output_path: Path) -> int:
        with (
            zipfile.ZipFile(source_path) as source,
            zipfile.ZipFile(output_path) as output,
        ):
            source_media = _media(source)
            output_media = _media(output)
        if output_media.keys() != source_media.keys():
            raise ValueError("Output media relationships are incomplete")
        for name, source_bytes in source_media.items():
            output_bytes = output_media[name]
            if source_bytes == output_bytes:
                raise ValueError("Source image bytes remain in output")
            if _image_size(source_bytes) != _image_size(output_bytes):
                raise ValueError("Replacement image dimensions changed")
        return len(source_media)


def _searchable_values(data: bytes) -> tuple[str, ...]:
    parser = etree.XMLParser(
        load_dtd=False,
        no_network=True,
        recover=False,
        resolve_entities=False,
    )
    root = etree.fromstring(data, parser=parser)
    paragraphs = tuple(
        "".join(element.itertext())
        for element in root.iter()
        if etree.QName(element).localname == "p"
    )
    text = tuple(value for value in root.itertext() if value)
    attributes = tuple(
        value for element in root.iter() for value in element.attrib.values()
    )
    return paragraphs + text + attributes


def _media(package: zipfile.ZipFile) -> dict[str, bytes]:
    return {
        name: package.read(name)
        for name in package.namelist()
        if name.startswith("word/media/") and not name.endswith("/")
    }


def _image_size(data: bytes) -> tuple[int, int]:
    with Image.open(BytesIO(data)) as image:
        return image.size


def _sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
