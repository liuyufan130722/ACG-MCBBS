import os

import pymysql
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join("env", "mysql.env"))

HOST = os.environ.get("host")
PORT = os.environ.get("port")
USER = os.environ.get("user")
PASSWORD = os.environ.get("pwd")
DATABASE = os.environ.get("db")


class Operation:
    def __init__(self) -> None:
        try:
            self.connection = pymysql.connect(
                host=HOST,
                port=int(PORT),
                user=USER,
                password=PASSWORD,
                db=DATABASE,
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor
            )
            self.cursor = self.connection.cursor()
        except Exception as e:
            raise OperationMysqlDatabaseError(e)
        
    def __enter__(self) -> pymysql.connect.cursor:
        if self.cursor:
            return self.cursor
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if not all([self.connection, self.cursor]):
            return
        self.connection.commit()
        self.cursor.close()
        self.connection.close()


class OperationMysqlDatabaseError(Exception):
    """操作MySQL数据库时发生的错误异常"""
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return f"操作MySQL数据库时发生错误：{self.message}。"
