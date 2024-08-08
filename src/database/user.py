from typing import *

from loguru import logger

from .operation import Operation


class UserDatabase(Operation):
    """用于与MySQL数据库中的用户数据交互的类。"""

    def __init__(self):
        """
        初始化一个 UserDatabase 实例。

        :raises OperationMysqlDatabaseError: 如果连接到数据库失败。
        """
        super().__init__()

    def create_user(
            self,
            username: str,
            email: str,
            is_admin: bool = False,
            **kwargs: dict
    ) -> bool:
        """
        创建一个新用户，并检查用户是否已存在。

        :param str username: 要创建的用户的用户名。
        :param str email: 要创建的用户的电子邮件。
        :param bool is_admin: 是否为管理员，默认为 False。
        :param kwargs: 可选参数，包括密码、key 和头像。

        :return: 如果成功创建用户，则返回 True；如果用户已存在或创建过程中出现错误，则返回 False。
        :rtype: bool

        :raises OperationMysqlDatabaseError: 如果执行SQL查询时出错。
        """
        try:
            # 解析可选参数
            password = kwargs.get('password', None)
            key = kwargs.get('key', None)
            avatar = kwargs.get('avatar', None)

            # 检查用户是否已存在
            existing_user = self.get_user(username)
            if existing_user:
                logger.error(f"用户 {username} 已存在！")
                return False  # 用户已存在，返回 False

            # 创建新用户
            with self.connection.cursor() as cursor:
                sql = "INSERT INTO users (username, email, is_admin, password, user_key, avatar) VALUES (%s, %s, %s, %s, %s, %s)"
                cursor.execute(sql, (username, email, is_admin, password, key, avatar))
                self.connection.commit()
                return True  # 用户创建成功，返回 True
        except Exception as e:
            logger.error(e)
            return False  # 创建用户过程中出现错误，返回 False

    def get_user(self, username: str) -> Union[dict, None]:
        """
        根据用户名从数据库中检索用户信息。

        :param str username: 要检索的用户的用户名。

        :return: 如果找到，返回包含用户信息的字典；否则返回 None。
        :rtype: dict

        :raises OperationMysqlDatabaseError: 如果执行SQL查询时出错。
        """
        try:
            with self.connection.cursor() as cursor:
                sql = "SELECT * FROM users WHERE username = %s"
                cursor.execute(sql, (username,))
                return cursor.fetchone()
        except Exception as e:
            logger.error(e)
            return None

    def delete_user(self, username: str) -> bool:
        """
        根据用户名从数据库中删除用户。

        :param str username: 要删除的用户的用户名。

        :return: 如果成功删除用户，则返回 True；否则返回 False。
        :rtype: bool

        :raises OperationMysqlDatabaseError: 如果执行SQL查询时出错。
        """
        try:
            with self.connection.cursor() as cursor:
                sql = "DELETE FROM users WHERE username = %s"
                cursor.execute(sql, (username,))
                self.connection.commit()
                return True
        except Exception as e:
            logger.error(e)
            return False
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        return super().__exit__(exc_type, exc_val, exc_tb)
