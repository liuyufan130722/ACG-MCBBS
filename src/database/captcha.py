from datetime import datetime, timedelta
from loguru import logger

from .operation import Operation


class CaptchaDataBase(Operation):
    def __init__(self) -> None:
        """
        对验证码数据的数据进行操作
        :return None
        """
        super().__init__()
    
    def get_data(self, username: str) -> dict:
        """
        通过用户名获取数据。
        :param username: str 用户名
        :return dict
        """
        query = """
            SELECT * FROM verification_code
            WHERE username = %s;
        """
        try:
            self.cursor.execute(query, (username, ))
            result = self.cursor.fetchone()
        except Exception as e:
            logger.error(e)
            return {}
        
        if result:
            return result
        else:
            return {}
        
    def create_data(
            self,
            email: str,
            username: str,
            code: str,
            valid_duration: int = 60
        ) -> bool:
        """
        创建新的验证码数据，并设置有效期。
        :param email: str 邮箱地址
        :param username: str 用户名
        :param code: str 验证码内容
        :param valid_duration: int 验证码有效时长（秒）
        :return: bool 插入是否成功
        """
        # 获取现在时间并生成过期时间。
        now = datetime.now()
        expires_at = now + timedelta(seconds=valid_duration)

        insert_query = """
            INSERT INTO Verification_code (email, username, code, created_at, expires_at)
            VALUES (%s, %s, %s, %s, %s)
        """

        try:
            self.cursor.execute(insert_query, (email, username, code, now, expires_at))
            self.connection.commit()  # 提交事务
            return True
        except Exception as e:
            logger.error(e)
            return False
        
    def delete_by_username(self, username: str) -> bool:
        """
        根据用户名删除验证码记录。
        :param username: str 用户名
        :return: bool
        """
        delete_query = """
            DELETE FROM Verification_code
            WHERE username = %s
        """
        try:
            self.cursor.execute(delete_query, (username,))
            self.connection.commit()  # 提交事务
            return True
        except Exception as e:
            logger.error(e)
            return False
        
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        return super().__exit__(exc_type, exc_val, exc_tb)