import os
import json
from datetime import datetime

from PIL import Image, ImageDraw, ImageFont, ImageFont

from src.methods.create import CreateKey


class Captcha:
    def __init__(self) -> None:
        """图片验证码"""
        self.generatePicDir = os.path.join(
            os.getcwd(), "static", "cache", "graphic_generate"
        )

    def generate(self) -> os.PathLike:
        """生成图片验证码"""
        randomPicName = "graphic" + CreateKey().generate_key() + ".jpg"
        randomPicPath = os.path.join(self.generatePicDir, randomPicName)
        # 生成验证码
        code = CreateKey(4).generate_key()
        # 生成图片
        img = Image.new("RGB", (200, 50), (255, 255, 255))
        draw = ImageDraw.Draw(img)
        # 选择要写入的字体
        font = ImageFont.truetype("arial.ttf", 36)
        # 绘制通过 `CreateKey` 生成的验证码
        draw.text((50, 10), code, (0, 0, 0), font=font)
        # 保存图片
        img.save(randomPicPath)
        # 将图片名和验证码的映射关系写入json文件
        self.writeMapping(code=code, pic=randomPicPath)
        return "static\\cache\\graphic_generate\\" + randomPicName
    
    def writeMapping(
            self,
            mappingTable: dict = None,
            code: str = None, 
            pic: os.PathLike = None
        ) -> None:
        """
        生成json文件映射图片和验证码
        :param mappingTable: 映射表
        :param code: 验证码
        :param pic: 图片
        :return: None
        """
        mappingJsonFilePath = os.path.join(
            self.generatePicDir, "mapping.json"
        )
        MappingTable = self.readMapping() if mappingTable == None else mappingTable
        if all([code, pic]):
            # 生成写入时间
            MappingTable[code] = {
                "pic": pic,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        # 写入映射文件
        with open(mappingJsonFilePath, "w+", encoding="utf-8") as wfp:
            wfp.write(json.dumps(MappingTable, indent=4, ensure_ascii=False))
            wfp.flush()

    def readMapping(self) -> dict:
        """读取映射文件"""
        mappingJsonFilePath = os.path.join(
            self.generatePicDir, "mapping.json"
        )
        # 判断映射文件是否存在
        if not os.path.isfile(mappingJsonFilePath):
            return {}
        
        # 读取映射文件
        with open(mappingJsonFilePath, "r", encoding="utf-8") as rfp:
            return json.loads(rfp.read())

    def verify(self, code: str) -> bool:
        """验证图片验证码"""
        MappingTable = self.scanExpiresCode()

        # 判断验证码是否存在
        if code not in MappingTable:
            return False
        # 验证成功后删除验证码 和 图片
        if os.path.isfile(MappingTable[code]['pic']):
            os.remove(MappingTable[code]['pic'])
        del MappingTable[code]

        # 写入映射文件
        self.writeMapping(mappingTable=MappingTable)
        return True

    def scanExpiresCode(self) -> dict:
        """扫描过期的验证码，并删除图片和映射表"""
        MappingTable = self.readMapping()
        for code in MappingTable.copy().keys():
            # 通过time计算生成时间大于3分钟的验证码
            generationTime = datetime.strptime(MappingTable[code]["time"], "%Y-%m-%d %H:%M:%S")
            if (datetime.now() - generationTime).total_seconds() > 180:
                # 删除图片和映射表
                if os.path.isfile(MappingTable[code]['pic']):
                    os.remove(MappingTable[code]['pic'])
                del MappingTable[code]
        
        # 写入映射文件
        self.writeMapping(mappingTable=MappingTable)
        return MappingTable
