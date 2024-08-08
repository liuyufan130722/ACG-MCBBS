from src.services.captcha import GraphicCaptcha

GC = GraphicCaptcha.Captcha()
print(GC.generate())
# print(GC.verify(""))