import re
import sys


RE_SPANX_VERB = re.compile('\<spanx style="verb"\>([^<]*)</spanx>')


def main(xml_filename_in: str, xml_filename_out: str) -> None:
    with open(xml_filename_in) as fin:
        xml_in = fin.read()

    xml_out = RE_SPANX_VERB.sub(lambda m: f'"{m.group(1).strip()}"', xml_in)

    with open(xml_filename_out, "w") as fout:
        fout.write(xml_out)


def usage() -> str:
    return (
        "Converts <spanx style=\"verb\"></spanx> tags to quotes in order to aid in the "
        "xml to text conversion performed by xml2rfc (which ignores spanx). \n\n"
        "Expected usage: python spanx_verb_to_quote.py xml_filename_in xml_filename_out"
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(usage())

    xml_filename_in, xml_filename_out = sys.argv[-2:]
    main(xml_filename_in, xml_filename_out)
