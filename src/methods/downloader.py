from typing import *

import requests
from loguru import logger

class Downloader:
    @staticmethod
    def download_file(url: str) -> bytes:
        """
        从给定的URL下载文件，并将其内容作为字节返回。

        :param str url: 要下载的文件的URL。
        :return: 下载的文件内容作为字节。
        :rtype: bytes
        """
        logger.info(f"下载文件: {url}")
        with requests.get(url) as response:
            if response.status_code == 200:
                return response.content
            
        return b''
    