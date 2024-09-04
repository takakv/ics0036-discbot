import csv
import os
from datetime import datetime

from dotenv import load_dotenv
import jwt

load_dotenv()
SECRET = os.getenv("JWT_SECRET")


def get_jwt(name: str, student_code: str) -> str:
    return jwt.encode({
        "exp": datetime(2024, 9, 10),
        "name": name,
        "studentCode": student_code,
    }, SECRET, algorithm="HS256")


def main():
    with open("students.csv") as sf, open("tokens.csv", "a") as tf:
        csv_reader = csv.reader(sf, delimiter=";")
        read_header = False
        for row in csv_reader:
            if not read_header:
                read_header = True
                continue

            token = get_jwt(f"{row[2]} {row[3]}", row[1])
            tf.write(f"{row[2]} {row[3]};{row[1]};{token}\n")


if __name__ == "__main__":
    main()
