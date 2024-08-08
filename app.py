import os

from flask import Flask
from flask import request, render_template, jsonify
from flask_cors import CORS
from loguru import logger

from src.database import captcha, user
from src.services.captcha import EmailCaptcha, GraphicCaptcha
from src.methods.create import CreateKey
from src.methods.downloader import Downloader

app = Flask(
    __name__,
    static_folder="static",
    template_folder="templates"
)
CORS(app)

@app.route("/send_code", methods=["POST"])
def send_code():
    """对指定邮件发送验证码"""
    result = {
        "code": 404,
        "content": "error"
    }
    email = request.json.get('email')
    username = request.json.get('username')
    
    if not all([email, username]):
        result["content"] = "参数错误！"
        return result
    
    VCS = EmailCaptcha.Captcha(captcha.VerificationCodeDataBase)
    send_result = VCS.send_code(email, username)
    if send_result is False:
        result['content'] = "发送失败！请检查邮件是否填写正确！"
    
    result['code'] = 200
    result["content"] = "发送成功！"
    return result


@app.route("/register", methods=["POST"])
def register():
    """注册用户"""
    result = {"code": 404}

    username = request.json.get("username")
    password = request.json.get("password")
    email = request.json.get("email")
    code = request.json.get("code")
    avatar_url = request.json.get("avatar_url")

    # 检查是否存在，用户名，密码，邮件。
    if not all([username, password, email, code]):
        result['content'] = "参数缺少！"
        return result
    
    # 验证验证码
    VCS = EmailCaptcha.Captcha(captcha.VerificationCodeDataBase)
    verify_result = VCS.verify_code(username, email, code)
    if verify_result['code'] != 200:
        result["content"] = verify_result['content']
        return result
    
    # 进行注册
    with user.UserDatabase() as useroper:
        create_result = useroper.create_user(
            username,
            email,
            False,
            password=password,
            key=CreateKey().generate_key(),
            avatar=Downloader.download_file(avatar_url) if avatar_url else b''
        )
    if create_result is False:
        result['content'] = "创建用户失败！"
        return result
    
    result["code"] = 200
    result["content"] = "创建成功！"
    return result


@app.route("/generate_graphic_captcha", methods=["POST", "GET"])
def generate_graphic_captcha():
    """生成图形验证码"""
    result = {"code": 404, "content": "error"}
    captcha_pic = GraphicCaptcha.Captcha().generate()
    if os.path.isfile(captcha_pic):
        logger.info(f"generate graphic captcha success: {captcha_pic}.")
        result["code"] = 200
        result["content"] = captcha_pic
        return jsonify(result)
    else:
        logger.error(f"generate graphic captcha failed: {captcha_pic}.")
    return result


@app.route("/verify_graphic_captcha", methods=["POST", "GET"])
def verify_graphic_captcha():
    """验证图形验证码"""
    result = {"code": 404, "content": "error"}
    code = request.json.get("code")
    if not code:
        result["content"] = "Missing parameter code."
        logger.error(result["content"])
        return result
    if not GraphicCaptcha.Captcha().verify(code):
        result["content"] = "Verification failed."
        logger.error(result["content"])
        return result
    logger.info(f"graphic captcha: code = {code}.")
    result["code"] = 200
    result['content'] = "success"
    return result


@app.route("/graphic_validation", methods=["GET"])
def graphic_validation():
    return render_template("graphic_validation.html")


if __name__ in "__main__":
    app.run(
        host="0.0.0.0",
        port=5665,
        debug=True
    )