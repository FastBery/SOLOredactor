#!/usr/bin/env python3

"""

SOLO 9 .ss9 editor



This tool understands the format used by SOLO 9 save files:

    01 | UTF-16 filename length | UTF-16 filename | RC4(UTF-16 XML + CRLF + CRC32)



The RC4 key is derived exactly like Solo.exe:

    CRC = custom CRC32 update, initial 0xFFFFFFFF

    seed = ~CRC

    key = 10 decimal digits of seed, each digit + 1



Examples:

    python solo_ss9_tool.py inspect save.ss9

    python solo_ss9_tool.py decrypt save.ss9 save.xml
    python solo_ss9_tool.py encrypt save.ss9 save.xml fixed.ss9

    python solo_ss9_tool.py set-user save.ss9 fixed.ss9 lastExercise 15.1

    python solo_ss9_tool.py set-user save.ss9 fixed.ss9 maxLesson 15

    python solo_ss9_tool.py set-typing save.ss9 fixed.ss9 14 1 2 mark=5 left=0

    python solo_ss9_tool.py verify fixed.ss9

"""



from __future__ import annotations



import argparse


import struct

from pathlib import Path

import xml.etree.ElementTree as ET





CLOSE_TAG = b"</SaveFile>".decode().encode("utf-16le")

UTF16_XML_DECL = '<?xml version="1.0" encoding="UTF-16"?>'

UTF16_CRLF = "\r\n".encode("utf-16le")


# Resolve input/output files relative to the folder containing this script.
SCRIPT_DIR = Path(__file__).resolve().parent

def local_path(path: Path) -> Path:
    """Resolve a relative path from the script directory; keep absolute paths unchanged."""
    if path.is_absolute():
        return path
    return SCRIPT_DIR / path





# Exact 256-entry table used by Solo.exe at 0x68F418.

CRC_TABLE = []

_POLY = 0xEDB88320

for _i in range(256):

    _x = _i

    for _ in range(8):

        _x = ((_x >> 1) ^ _POLY) if (_x & 1) else (_x >> 1)

    CRC_TABLE.append(_x & 0xFFFFFFFF)





def solo_crc(data: bytes, init: int = 0xFFFFFFFF) -> int:

    """Exact CRC update used by Solo.exe 0042A4B8."""

    crc = init & 0xFFFFFFFF

    for byte in data:

        crc = (

            CRC_TABLE[((crc >> 24) ^ byte) & 0xFF]

            ^ ((crc << 8) & 0xFFFFFFFF)

        )

    return crc & 0xFFFFFFFF





def make_key(filename: str) -> bytes:

    """

    Reproduce 0045D554 -> 0042B344:

      - hash UTF-16LE filename;

      - invert CRC;

      - encode decimal digits as digit+1, ten bytes total.

    """

    crc = solo_crc(filename.encode("utf-16le"), 0xFFFFFFFF)

    seed = (~crc) & 0xFFFFFFFF



    key = bytearray(10)

    for i in range(10):

        key[9 - i] = (seed % 10) + 1

        seed //= 10

    return bytes(key)





def rc4(data: bytes, key: bytes) -> bytes:

    """Exact RC4 core used by Solo.exe 0042B4FC."""

    if not key:

        raise ValueError("RC4 key is empty")



    s = list(range(256))

    j = 0



    # KSA

    for i in range(256):

        j = (j + s[i] + key[i % len(key)]) & 0xFF

        s[i], s[j] = s[j], s[i]



    # PRGA

    out = bytearray(len(data))

    i = 0

    j = 0

    for n, value in enumerate(data):

        i = (i + 1) & 0xFF

        j = (j + s[i]) & 0xFF

        s[i], s[j] = s[j], s[i]

        out[n] = value ^ s[(s[i] + s[j]) & 0xFF]



    return bytes(out)





def parse_container(raw: bytes) -> tuple[str, int, bytes, bytes, bytes, int, int]:

    """

    Return:

      filename, body_offset, key, plaintext_body,

      xml_bytes_without_BOM, stored_crc, calculated_crc

    """

    if len(raw) < 4:

        raise ValueError("File is too small")

    if raw[0] != 1:

        raise ValueError(f"Unexpected .ss9 version/header byte: {raw[0]:02X}")



    name_units = raw[1]

    name_start = 2

    name_end = name_start + name_units * 2

    if name_end > len(raw):

        raise ValueError("Truncated filename header")



    filename = raw[name_start:name_end].decode("utf-16le")

    body_offset = name_end



    key = make_key(filename)

    body = rc4(raw[body_offset:], key)



    close_pos = body.find(CLOSE_TAG)

    if close_pos < 0:

        raise ValueError(

            "RC4 decryption did not produce </SaveFile>. "

            "The file may use an unsupported version."

        )



    xml_end = close_pos + len(CLOSE_TAG)

    xml_bytes = body[:xml_end]



    # The encrypted payload is:
    #   UTF-16LE XML (+ BOM) + CRLF + 4-byte CRC.
    # The BOM is included in the CRC input.
    xml_for_crc = xml_bytes

    tail = body[xml_end:]

    if len(tail) != 8 or tail[:4] != UTF16_CRLF:

        raise ValueError(

            f"Unexpected decrypted footer: expected 8 bytes (CRLF+CRC), got {len(tail)}"

        )



    stored_crc = struct.unpack("<I", tail[4:])[0]

    calculated_crc = (~solo_crc(xml_for_crc + UTF16_CRLF, 0xFFFFFFFF)) & 0xFFFFFFFF



    return (

        filename,

        body_offset,

        key,

        body,

        xml_bytes,

        stored_crc,

        calculated_crc,

    )





def load_xml_text(path: Path) -> tuple[str, str, bytes, bytes, ET.Element]:

    raw = path.read_bytes()

    filename, body_offset, key, body, xml_bytes, stored_crc, calculated_crc = parse_container(raw)



    if stored_crc != calculated_crc:

        raise ValueError(

            f"CRC mismatch: stored={stored_crc:08X}, calculated={calculated_crc:08X}"

        )



    try:

        text = xml_bytes.decode("utf-16")

    except UnicodeDecodeError:

        text = xml_bytes.decode("utf-16le")



    # Keep the declaration exactly as text; ElementTree parses the document fine.

    root = ET.fromstring(text)

    return filename, text, key, body, root





def serialize_xml(root: ET.Element) -> bytes:

    """

    SOLO's XML is compact (no pretty indentation), UTF-16LE with BOM.

    Rebuild a compact document with the same XML declaration.

    """

    content = ET.tostring(root, encoding="unicode", short_empty_elements=True)

    text = UTF16_XML_DECL + "\r\n" + content

    return b"\xFF\xFE" + text.encode("utf-16le")





def build_container(filename: str, xml_bytes: bytes) -> bytes:

    """

    Build a fresh .ss9 container with the embedded filename and a valid CRC.

    """

    name_bytes = filename.encode("utf-16le")

    if len(name_bytes) // 2 > 255:

        raise ValueError("Embedded filename is too long for the .ss9 header")



    if not xml_bytes.startswith(b"\xFF\xFE"):

        xml_bytes = b"\xFF\xFE" + xml_bytes



    if not xml_bytes[2:].endswith(b">\x00"):

        raise ValueError("XML data looks invalid")



    # Ensure the XML footer is exactly CRLF + CRC.

    xml_for_crc = xml_bytes

    crc = (~solo_crc(xml_for_crc + UTF16_CRLF, 0xFFFFFFFF)) & 0xFFFFFFFF

    plain_body = xml_bytes + UTF16_CRLF + struct.pack("<I", crc)



    header = bytes([1, len(name_bytes) // 2]) + name_bytes

    key = make_key(filename)

    return header + rc4(plain_body, key)





def save_root(root: ET.Element, filename: str, out_path: Path) -> None:

    xml_bytes = serialize_xml(root)

    output = build_container(filename, xml_bytes)

    out_path.write_bytes(output)





def find_user(root: ET.Element) -> ET.Element:

    user = root.find("user")

    if user is None:

        raise ValueError("No <user> element found")

    return user





def find_typing(root: ET.Element, lesson: int, exercise: int, attempt: int) -> ET.Element:

    course = root.find("course")

    if course is None:

        raise ValueError("No <course> element found")



    lesson_el = next(

        (x for x in course.findall("lesson") if x.get("number") == str(lesson)),

        None,

    )

    if lesson_el is None:

        raise ValueError(f"Lesson {lesson} not found")



    exercise_el = next(

        (x for x in lesson_el.findall("exercise") if x.get("number") == str(exercise)),

        None,

    )

    if exercise_el is None:

        raise ValueError(f"Exercise {lesson}.{exercise} not found")



    typings = exercise_el.findall("typing")

    if attempt < 1 or attempt > len(typings):

        raise ValueError(

            f"Attempt {attempt} not found for {lesson}.{exercise}; "

            f"available attempts: {len(typings)}"

        )



    return typings[attempt - 1]





def cmd_verify(path: Path) -> None:

    raw = path.read_bytes()

    filename, body_offset, key, body, xml_bytes, stored, calculated = parse_container(raw)

    print(f"File:        {path}")

    print(f"Embedded:    {filename}")

    print(f"Body offset: 0x{body_offset:X}")

    print(f"RC4 key:     {key.hex(' ')}")

    print(f"Stored CRC:  {stored:08X}")

    print(f"Calc CRC:    {calculated:08X}")

    print("Status:      OK" if stored == calculated else "Status:      BAD")





def cmd_inspect(path: Path) -> None:

    raw = path.read_bytes()

    filename, body_offset, key, body, xml_bytes, stored, calculated = parse_container(raw)

    root = ET.fromstring(xml_bytes.decode("utf-16"))



    user = find_user(root)

    typ = list(root.iter("typing"))

    exercises = list(root.iter("exercise"))

    errors = list(root.iter("error"))



    print(f"File:        {path}")

    print(f"Embedded:    {filename}")

    print(f"Size:        {len(raw)} bytes")

    print(f"Body offset: 0x{body_offset:X}")

    print(f"RC4 key:     {key.hex(' ')}")

    print(f"CRC:         {'OK' if stored == calculated else 'BAD'} ({stored:08X})")

    print()

    print("User:")

    for field in (

        "identifier", "surname", "maxLesson", "repeatLesson", "repeatIter",

        "repeatExerciseCount", "currentDelay", "course", "lastExercise",

    ):

        if field in user.attrib:

            print(f"  {field}: {user.attrib[field]}")



    print()

    print(f"Lessons:     {len(root.findall('./course/lesson'))}")

    print(f"Exercises:   {len(exercises)}")

    print(f"Typing rows: {len(typ)}")

    print(f"Errors:      {len(errors)}")





def cmd_decrypt(path: Path, out_path: Path) -> None:

    raw = path.read_bytes()

    filename, body_offset, key, body, xml_bytes, stored, calculated = parse_container(raw)

    if stored != calculated:

        raise ValueError("Refusing to export an invalid save (CRC mismatch).")

    text = xml_bytes.decode("utf-16")

    out_path.write_text(text, encoding="utf-8-sig", newline="")

    print(f"Decrypted XML written to: {out_path}")





def cmd_encrypt(source_path: Path, xml_path: Path, out_path: Path) -> None:
    """Rebuild an .ss9 using the embedded filename from the original save."""
    raw = source_path.read_bytes()
    filename, body_offset, key, body, xml_bytes, stored, calculated = parse_container(raw)
    if stored != calculated:
        raise ValueError("Refusing to use an invalid source save (CRC mismatch).")

    xml_raw = xml_path.read_bytes()
    # Accept UTF-8, UTF-8 with BOM, or UTF-16 XML exported by other tools.
    if xml_raw.startswith(b"\xFF\xFE") or xml_raw.startswith(b"\xFE\xFF"):
        text = xml_raw.decode("utf-16")
    else:
        text = xml_raw.decode("utf-8-sig")

    root = ET.fromstring(text)
    save_root(root, filename, out_path)
    print(f"Encrypted .ss9 written to: {out_path}")
    cmd_verify(out_path)


def cmd_set_user(path: Path, out_path: Path, field: str, value: str) -> None:

    filename, text, key, body, root = load_xml_text(path)

    user = find_user(root)



    if field not in user.attrib:

        raise ValueError(

            f"User field {field!r} does not exist. "

            f"Known fields: {', '.join(user.attrib.keys())}"

        )



    user.set(field, value)

    save_root(root, filename, out_path)

    cmd_verify(out_path)





def cmd_set_typing(

    path: Path,

    out_path: Path,

    lesson: int,

    exercise: int,

    attempt: int,

    changes: list[str],

) -> None:

    filename, text, key, body, root = load_xml_text(path)

    typing = find_typing(root, lesson, exercise, attempt)



    if not changes:

        raise ValueError("At least one ATTRIBUTE=VALUE change is required.")



    for assignment in changes:

        if "=" not in assignment:

            raise ValueError(f"Invalid change {assignment!r}; use ATTRIBUTE=VALUE")

        attr, value = assignment.split("=", 1)

        if not attr:

            raise ValueError(f"Invalid empty attribute in {assignment!r}")

        if attr not in typing.attrib:

            raise ValueError(

                f"Typing attribute {attr!r} does not exist. "

                f"Known attributes: {', '.join(typing.attrib.keys())}"

            )

        typing.set(attr, value)



    save_root(root, filename, out_path)

    cmd_verify(out_path)






def list_saves() -> list[Path]:
    return sorted(SCRIPT_DIR.glob("*.ss9"))


def choose_file(files: list[Path], title: str) -> Path | None:
    if not files:
        print("\nСейвы *.ss9 не найдены рядом со скриптом.")
        return None
    print(f"\n{title}")
    for i, f in enumerate(files, 1):
        print(f"  {i}. {f.name}")
    print("  0. Отмена")
    while True:
        try:
            n = int(input("\nНомер файла: ").strip())
            if n == 0:
                return None
            if 1 <= n <= len(files):
                return files[n - 1]
        except ValueError:
            pass
        print("Введите номер из списка.")


def interactive_mode() -> int:
    """Simple menu for users who don't want to remember command-line syntax."""
    while True:
        print("\n" + "=" * 58)
        print("        LittleMaid / SOLO 9 — редактор сейвов")
        print("=" * 58)
        print("  1. Посмотреть информацию о сейве")
        print("  2. Расшифровать сейв → XML для редактирования")
        print("  3. Собрать XML обратно → .ss9")
        print("  4. Проверить .ss9")
        print("  5. Быстро изменить параметр пользователя")
        print("  6. Выйти")

        choice = input("\nВыберите действие [1-6]: ").strip()

        try:
            if choice == "1":
                f = choose_file(list_saves(), "Выберите сейв:")
                if f:
                    print()
                    cmd_inspect(f)

            elif choice == "2":
                f = choose_file(list_saves(), "Какой сейв расшифровать?")
                if f:
                    out = f.with_suffix(".xml")
                    if out.exists():
                        answer = input(f"{out.name} уже существует. Перезаписать? [д/н]: ").strip().lower()
                        if answer not in ("д", "да", "y", "yes"):
                            continue
                    cmd_decrypt(f, out)
                    print(f"\nГотово. Откройте {out.name}, внесите изменения и сохраните файл.")

            elif choice == "3":
                xmls = sorted(SCRIPT_DIR.glob("*.xml"))
                if not xmls:
                    print("\nXML-файлы рядом со скриптом не найдены.")
                    continue
                xml = choose_file(xmls, "Выберите отредактированный XML:")
                if not xml:
                    continue
                source = choose_file(list_saves(), "Выберите исходный .ss9, из которого взять формат:")
                if not source:
                    continue
                out = source.with_name(source.stem + "_edited.ss9")
                if out.exists():
                    answer = input(f"{out.name} уже существует. Перезаписать? [д/н]: ").strip().lower()
                    if answer not in ("д", "да", "y", "yes"):
                        continue
                cmd_encrypt(source, xml, out)
                print(f"\nГотово! Новый сейв: {out.name}")
                print("Его можно скопировать в папку SOLO и использовать как обычный .ss9.")

            elif choice == "4":
                f = choose_file(list_saves() + sorted(SCRIPT_DIR.glob("*_edited.ss9")), "Выберите сейв для проверки:")
                if f:
                    print()
                    cmd_verify(f)

            elif choice == "5":
                f = choose_file(list_saves(), "Какой сейв изменить?")
                if not f:
                    continue
                _, _, _, _, root = load_xml_text(f)
                user = find_user(root)
                fields = list(user.attrib.keys())
                print("\nДоступные параметры:")
                for i, field in enumerate(fields, 1):
                    print(f"  {i}. {field} = {user.attrib[field]}")
                try:
                    n = int(input("\nНомер параметра (0 — отмена): ").strip())
                    if n == 0:
                        continue
                    field = fields[n - 1]
                except (ValueError, IndexError):
                    print("Неверный номер.")
                    continue
                value = input(f"Новое значение для {field}: ")
                out = f.with_name(f.stem + "_edited.ss9")
                cmd_set_user(f, out, field, value)
                print(f"\nГотово! Новый сейв: {out.name}")

            elif choice == "6":
                print("До встречи!")
                return 0

            else:
                print("Выберите пункт от 1 до 6.")

        except Exception as e:
            print(f"\nОшибка: {e}")

        input("\nНажмите Enter, чтобы продолжить...")


def main() -> int:

    if len(__import__("sys").argv) == 1:
        return interactive_mode()

    parser = argparse.ArgumentParser(description="SOLO 9 .ss9 save editor")

    sub = parser.add_subparsers(dest="cmd", required=True)



    p = sub.add_parser("verify", help="Verify encryption and CRC")

    p.add_argument("save", type=Path)



    p = sub.add_parser("inspect", help="Show save contents summary")

    p.add_argument("save", type=Path)



    p = sub.add_parser("decrypt", help="Export decrypted XML")

    p.add_argument("save", type=Path)

    p.add_argument("output", type=Path)



    p = sub.add_parser("encrypt", help="Build a new .ss9 from edited XML; preserve embedded filename from source save")
    p.add_argument("source", type=Path, help="Original valid .ss9 save")
    p.add_argument("xml", type=Path, help="Edited XML file")
    p.add_argument("output", type=Path, help="Output .ss9 file")

    p = sub.add_parser("set-user", help="Change an attribute of <user>")

    p.add_argument("save", type=Path)

    p.add_argument("output", type=Path)

    p.add_argument("field")

    p.add_argument("value")



    p = sub.add_parser("set-typing", help="Change attributes of a typing attempt")

    p.add_argument("save", type=Path)

    p.add_argument("output", type=Path)

    p.add_argument("lesson", type=int)

    p.add_argument("exercise", type=int)

    p.add_argument("attempt", type=int, help="1-based attempt number")

    p.add_argument("changes", nargs="+", metavar="ATTRIBUTE=VALUE")



    args = parser.parse_args()

    # Save/output names are resolved relative to this script.
    if hasattr(args, "save"):
        args.save = local_path(args.save)
    if hasattr(args, "source"):
        args.source = local_path(args.source)
    if hasattr(args, "output"):
        args.output = local_path(args.output)
    if hasattr(args, "xml"):
        args.xml = local_path(args.xml)




    if args.cmd == "verify":

        cmd_verify(args.save)

    elif args.cmd == "inspect":

        cmd_inspect(args.save)

    elif args.cmd == "decrypt":

        cmd_decrypt(args.save, args.output)

    elif args.cmd == "encrypt":

        cmd_encrypt(args.source, args.xml, args.output)

    elif args.cmd == "set-user":

        cmd_set_user(args.save, args.output, args.field, args.value)

    elif args.cmd == "set-typing":

        cmd_set_typing(

            args.save, args.output,

            args.lesson, args.exercise, args.attempt, args.changes

        )

    return 0





if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FileNotFoundError as e:
        print(f"Ошибка: файл не найден: {e.filename}")
        print("Проверь, что *.ss9 лежит рядом со скриптом.")
        raise SystemExit(2)
    except Exception as e:
        print(f"Ошибка: {e}")
        raise SystemExit(1)
