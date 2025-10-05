import mysql.connector
from dotenv import load_dotenv
import os

class MyDatabase:
    @staticmethod
    def get_conn():
        env_path = os.path.join(os.path.dirname(__file__), '..', 'mysql.txt')
        load_dotenv(dotenv_path=env_path)

        conn = mysql.connector.connect(
            host=os.getenv("MYSQL_HOST"),
            user=os.getenv("MYSQL_USER"),
            password=os.getenv("MYSQL_PASSWORD"),
            database=os.getenv("MYSQL_DB")
        )

        return conn