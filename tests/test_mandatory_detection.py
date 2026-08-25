import pytest

from pii_redactor.bootstrap import build_pii_detector


@pytest.fixture(scope="module")
def detector():
    return build_pii_detector()


@pytest.mark.parametrize(
    ("entity_type", "value", "text"),
    [
        ("PERSON", "Rahul Sharma", "Applicant name: Rahul Sharma"),
        (
            "EMAIL_ADDRESS",
            "rashi.patil@example.com",
            "Email: rashi.patil@example.com",
        ),
        ("PHONE_NUMBER", "+91 98765 43210", "Phone: +91 98765 43210"),
        (
            "ORGANIZATION",
            "Tata Consultancy Services Limited",
            "Company: Tata Consultancy Services Limited",
        ),
        (
            "PHYSICAL_ADDRESS",
            "12 MG Road, Bengaluru, Karnataka 560001",
            "Mailing address: 12 MG Road, Bengaluru, Karnataka 560001",
        ),
        ("US_SSN", "219-09-9999", "SSN: 219-09-9999"),
        (
            "CREDIT_CARD",
            "4111 1111 1111 1111",
            "Credit card: 4111 1111 1111 1111",
        ),
        (
            "DATE_OF_BIRTH",
            "14 September 1988",
            "Date of birth: 14 September 1988",
        ),
        ("IP_ADDRESS", "192.0.2.10", "Server IP: 192.0.2.10"),
        ("IP_ADDRESS", "2001:db8::1234", "Server IP: 2001:db8::1234"),
        ("IN_PAN", "AAAPA1234A", "PAN: AAAPA1234A"),
        ("IN_AADHAAR", "2345 6789 0124", "Aadhaar: 2345 6789 0124"),
        ("IN_DIN", "01234567", "DIN: 01234567"),
        ("IN_CIN", "L12345MH2020PLC123456", "CIN: L12345MH2020PLC123456"),
    ],
)
def test_detects_required_and_document_specific_pii(detector, entity_type, value, text):
    findings = detector.detect(text)

    matching = [item for item in findings if item.entity_type == entity_type]
    assert any(text[item.start : item.end] == value for item in matching)
    assert all(item.recognizer_name and 0 < item.score <= 1 for item in matching)


def test_detects_prospectus_style_indian_contact_block(detector):
    text = (
        "Director: Rahul Sharma\n"
        "Company: Tata Consultancy Services Limited\n"
        "Email: investors@example.com\n"
        "Phone: +91 98765 43210\n"
        "Registered office:\n"
        "4th Floor, Tower B,\n"
        "123 MG Road, Bengaluru, Karnataka 560001"
    )

    findings = detector.detect(text)
    detected_types = {item.entity_type for item in findings}
    detected_values = {
        (item.entity_type, text[item.start : item.end]) for item in findings
    }

    assert {
        "PERSON",
        "ORGANIZATION",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "PHYSICAL_ADDRESS",
    } <= detected_types
    assert {
        ("PERSON", "Rahul Sharma"),
        ("ORGANIZATION", "Tata Consultancy Services Limited"),
        ("EMAIL_ADDRESS", "investors@example.com"),
        ("PHONE_NUMBER", "+91 98765 43210"),
        (
            "PHYSICAL_ADDRESS",
            "4th Floor, Tower B,\n"
            "123 MG Road, Bengaluru, Karnataka 560001",
        ),
    } <= detected_values
    assert all(item.recognizer_name for item in findings)
    assert {item.context for item in findings} >= {"email", "phone", "office"}
    assert findings == detector.detect(text)
    assert all(left.end <= right.start for left, right in zip(findings, findings[1:]))


def test_ignores_prospectus_numbers_dates_and_generic_company(detector):
    text = (
        "On 31 March 2025, the share price was Rs. 1,250. "
        "Registration order 1234567890 was approved. "
        "The Company issued 500 shares."
    )

    detected_types = {item.entity_type for item in detector.detect(text)}

    assert detected_types.isdisjoint(
        {"DATE_OF_BIRTH", "PHONE_NUMBER", "CREDIT_CARD", "ORGANIZATION"}
    )
