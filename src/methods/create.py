class CreateKey:
    def __init__(self, length=16) -> None:
        """
        初始化类，设置密钥长度和字符集，默认生成10位大小写字母和数字混合的密钥。
        """
        self.length = length
        self.chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

    def generate_key(self) -> str:
        """
        生成随机密钥的方法。
        """
        import random
        return ''.join(random.choice(self.chars) for _ in range(self.length))
