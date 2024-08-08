import os
import random
import time
import ssl
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import Header
from loguru import logger
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join("env", "email.env"))
SENDER = os.environ.get('SENDER')
IMAP_SMTP_CODE = os.environ.get('IMAP_SMTP_CODE')
SMTP_SERVER = os.environ.get('SMTP_SERVER')


class EmailEvent:
    def __init__(
            self,
            smtp_server: str = SMTP_SERVER,
            port: int = 465,
            sender: str = SENDER
        ) -> None:
        """
        发送邮件事件
        """
        self.smtpServer = smtp_server
        self.port = port
        self.sender = sender
        self.message = MIMEMultipart()
        self.message['From'] = Header(sender)
    
    def setSubject(self, subject: str) -> None:
        """
        设置主题
        """
        self.message['Subject'] = Header(subject)
    
    def setContent(self, content_text: str = None, content_html: str = None) -> None:
        """
        设置邮件内容
        """
        if not content_html:
            self.message.attach(MIMEText(content_text, "plain", "utf-8"))
        if not content_text:
            self.message.attach(MIMEText(content_html, "html", "utf-8"))
        else:
            self.message.attach(MIMEText(content_text, "plain", "utf-8"))
            self.message.attach(MIMEText(content_html, "html", "utf-8"))

    def send(self, receivers: list) -> bool:
        """
        发送，可对多个邮件发送
        """
        # 加密上下文
        context = ssl.create_default_context()
        try:
            server = smtplib.SMTP_SSL(self.smtpServer, self.port, context=context)
            server.login(self.sender, IMAP_SMTP_CODE)
            
            # 发送邮件
            for receiver in receivers:
                server.sendmail(self.sender, receiver, self.message.as_string())
                logger.info(f"成功发送信息至邮件：{receiver}")
                time.sleep(random.randint(1, 5))
            return True

        except Exception as e:
            return False

        finally:
            server.quit()


def sendEmailVerufucationCode(receiver: str, code: str) -> bool:
    """
    发送邮箱验证码
    :params
        receiver str: 要发送至的邮件
        code str: 验证码
    """
    # 创建一个带附件的MIMEMultipart对象
    msg = MIMEMultipart()
    msg['From'] = Header(SENDER)
    msg['To'] = Header(receiver)
    msg['Subject'] = Header("来自CraftBBS的邮箱验证码", 'utf-8')  # 邮件主题，支持中文

    # 邮件正文内容
    text_content = f"这是你的邮箱验证码：{code}"
    html_content = f"<html><body><p>这是你的邮箱验证码：{code}</p></body></html>"

    # 将文本和HTML内容加入到MIME消息体中
    part1 = MIMEText(text_content, 'plain', 'utf-8')
    part2 = MIMEText(html_content, 'html', 'utf-8')
    msg.attach(part1)
    msg.attach(part2)

    # 连接SMTP服务器并登录
    smtp_server = 'smtp.163.com'
    smtp_port = 465  # SSL端口，默认情况下网易要求使用SSL加密连接
    context = ssl.create_default_context()  # 加密上下文
    try:
        server = smtplib.SMTP_SSL(smtp_server, smtp_port, context=context)
        server.login(SENDER, IMAP_SMTP_CODE)
        
        # 发送邮件
        server.sendmail(SENDER, receiver, msg.as_string())
        return True

    except Exception as e:
        return False

    finally:
        server.quit()


if __name__ in "__main__":
    email_event = EmailEvent()
    email_event.setSubject("来自PYmili的测试！")
    email_event.setContent("此次为测试内容！")
    print(email_event.send([]))
