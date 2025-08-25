import csv
import os
from datetime import datetime
from zoneinfo import ZoneInfo

import jwt
from dotenv import load_dotenv

load_dotenv()
SECRET = os.getenv("JWT_SECRET")


def get_jwt(name: str, uni_id: str, student_code: str, id_code: str) -> str:
    return jwt.encode({
        "exp": datetime(2025, 9, 9, tzinfo=ZoneInfo("Europe/Tallinn")),
        "name": name,
        "uniID": uni_id,
        "studentCode": student_code,
        "idCode": id_code,
    }, SECRET, algorithm="HS256")


def get_student_token(first_name: str, last_name: str, id_code: str) -> str | None:
    with open("../students.csv") as sf:
        csv_reader = csv.reader(sf, delimiter=";")
        for row in csv_reader:
            if row[3].lower() == last_name.lower() and row[2].lower() == first_name.lower():
                return get_jwt(f"{row[2]} {row[3]}", row[2], row[1], id_code)
    return None


def main():
    with open("../students.csv") as sf, open("tokens.csv", "a") as tf:
        csv_reader = csv.reader(sf, delimiter=";")
        read_header = False
        for row in csv_reader:
            if not read_header:
                read_header = True
                continue

            token = get_jwt(f"{row[2]} {row[3]}", row[2], row[1])
            tf.write(f"{row[2]} {row[3]};{row[1]};{token}\n")


if __name__ == "__main__":
    main()
