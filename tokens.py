import os
from datetime import datetime

from dotenv import load_dotenv
import jwt

load_dotenv()
SECRET = os.getenv("JWT_SECRET")

def main():
    encoded = jwt.encode({
        "exp": datetime(2024, 9, 16),
        "name": "Firstname Lastname",
        "studentCode": "test123"
    }, SECRET, algorithm="HS256")
    print(encoded)


if __name__ == "__main__":
    main()
