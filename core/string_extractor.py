import re

class StringExtractor:
    """
    Extract readable strings from binary data (ASCII, UTF-16, and fake Unicode).
    """

    def __init__(self, min_length: int = 4):
        self.min_length = min_length

    # ************** ASCII STRINGS ************************
    def extract_ascii_strings(self, data: bytes) -> list:
        """
        Extract printable ASCII strings using regex (reliable).
        """
        pattern = rb"[ -~]{%d,}" % self.min_length
        matches = re.findall(pattern, data)

        return [m.decode("ascii", errors="ignore") for m in matches]

    # ************* UTF-16 (REAL BINARY) ******************
    def extract_utf16_strings(self, data: bytes) -> list:
        """
        Extract real UTF-16LE strings (e.g. h\x00e\x00l\x00l\x00o\x00)
        """
        pattern = rb"(?:[\x20-\x7E]\x00){%d,}" % self.min_length
        matches = re.findall(pattern, data)

        results = []
        for m in matches:
            try:
                decoded = m.decode("utf-16le")
                results.append(decoded)
            except:
                continue

        return results

    # *************** FAKE UNICODE (\0 TEXT STYLE) *********************
    def extract_fake_unicode(self, data: bytes) -> list:
        """
        Extract strings like: h\\0t\\0t\\0p\\0 and convert to normal text.
        """
        # the latin-1 maps every byte directly does not break bytes 
        text = data.decode("latin-1", errors="ignore")

        pattern = r"(?:[ -~]\\0){%d,}" % self.min_length
        matches = re.findall(pattern, text)

        cleaned = []
        for m in matches:
            cleaned.append(m.replace("\\0", ""))  # remove \0

        return cleaned

    # ***************** MAIN FUNCTION **********************
    def extract_all_strings(self, data: bytes) -> list:
        """
        Combine all extraction methods and clean results.
        """
        ascii_strings = self.extract_ascii_strings(data)
        utf16_strings = self.extract_utf16_strings(data)
        fake_unicode_strings = self.extract_fake_unicode(data)

        # Merge all
        all_strings = set(ascii_strings + utf16_strings + fake_unicode_strings)

        # Remove broken strings (like raw \0)
        final_strings = []
        for s in all_strings:
            if "\\0" in s:
                continue
            if len(s.strip()) >= self.min_length:
                final_strings.append(s.strip())

        return sorted(final_strings)

