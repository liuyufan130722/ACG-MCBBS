from datetime import datetime
import random
import string
from typing import *

from . import send

class Captcha:
    def __init__(
            self,
            database_func: Any,
            code_length: int = 8,
            valid_duration: int = 60
        ):
        """
        初始化验证码服务类
        :param database_func: 数据库函数方法
        :param code_length: 验证码长度，默认为8位
        :param valid_duration: 验证码有效时间（单位：秒），默认为60秒
        """
        self.database_func = database_func
        self.code_length = code_length
        self.valid_duration = valid_duration

    def generate_code(self) -> str:
        """
        生成随机验证码
        :return str
        """
        chars = string.digits + string.ascii_letters
        return ''.join(random.choice(chars) for _ in range(self.code_length))

    def send_code(self, to_email_adder: str, username: str) -> bool:
        """
        生成并发送验证码到指定电话号码
        
        :param to_email_adder str: 要发送至的邮件地址
        :return bool
        """
        code = self.generate_code()

        # 发送邮件如果成功则保存。
        send_result = send.sendEmailVerufucationCode(to_email_adder, code)
        if send_result is True:
            # 保存数据到数据库
            with self.database_func() as db_func:
                func_result = db_func.create_data(to_email_adder, username, code, self.valid_duration)
                if func_result is False:
                    return func_result
        
        return send_result

    def verify_code(self, username: str, email_adder: str, provided_code: str) -> List:
        """
        验证提供的验证码是否正确

        :param username: str 用户名
        :param email_adder str: 电子邮件地址
        :param provided_code str: 需要验证的码
        :return List
        """
        result = {
            "code": 404,
            "content": ""
        }
        with self.database_func() as db_func:
            code_data = db_func.get_data(username)

        if not code_data:
            result['content'] = "不存在！"
            return result
        
        if code_data.get('email') != email_adder:
            result['content'] = "邮箱不存在！"
            return result
        
        if code_data.get('is_used') is True:
            result['content'] = "验证码已使用过！"
            return result
        
        if code_data.get('code') != provided_code:
            result['content'] = "验证码错误！"
            return result

        if code_data['expires_at'] > datetime.now():
            result['content'] = "验证码已超时!"
            return result

        result['code'] = 200
        result['content'] = "通过验证！"
        return result


if __name__ in "__main__":
    # 使用示例
    service = Captcha()
    send_result = service.send_code('2097632843@qq.com')
    if send_result is True:
        print("发送成功！")
    else:
        print("发送失败！")