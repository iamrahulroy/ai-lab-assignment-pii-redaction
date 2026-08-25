from collections.abc import Callable
from pathlib import Path

from docx import Document
from docx.text.paragraph import Paragraph

from pii_redactor.domain import PseudonymizedText, TextReplacement


class DocxRedactor:
    def redact(
        self,
        source_path: Path,
        output_path: Path,
        transform: Callable[[str], PseudonymizedText],
    ) -> None:
        document = Document(source_path)
        for paragraph in document.paragraphs:
            transformed = transform(paragraph.text)
            self._apply_replacements(paragraph, transformed.replacements)
            if paragraph.text != transformed.text:
                raise ValueError("DOCX patch does not match Presidio anonymizer output")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        document.save(output_path)

    @staticmethod
    def _apply_replacements(
        paragraph: Paragraph, replacements: tuple[TextReplacement, ...]
    ) -> None:
        ordered = sorted(replacements, key=lambda item: item.start, reverse=True)
        for replacement in ordered:
            DocxRedactor._replace_span(paragraph, replacement)

    @staticmethod
    def _replace_span(paragraph: Paragraph, replacement: TextReplacement) -> None:
        runs = paragraph.runs
        boundaries: list[tuple[int, int]] = []
        cursor = 0
        for run in runs:
            boundaries.append((cursor, cursor + len(run.text)))
            cursor += len(run.text)

        affected = [
            index
            for index, (start, end) in enumerate(boundaries)
            if replacement.start < end and replacement.end > start
        ]
        if not affected:
            raise ValueError("Replacement span does not intersect a DOCX text run")

        first_index = affected[0]
        last_index = affected[-1]
        first_start, _ = boundaries[first_index]
        last_start, _ = boundaries[last_index]
        prefix = runs[first_index].text[: replacement.start - first_start]
        suffix = runs[last_index].text[replacement.end - last_start :]

        if first_index == last_index:
            runs[first_index].text = prefix + replacement.value + suffix
            return

        runs[first_index].text = prefix + replacement.value
        for index in affected[1:-1]:
            runs[index].text = ""
        runs[last_index].text = suffix
