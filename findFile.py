import re


class FindFile:
    def __init__(self, response):
        self.response = response
        self.files = []

    def filesFound(self, ):
        for file in re.findall("nvdcve-1.1-[a-z0-9]*\.json\.zip", self.response.text):
            self.files.append(file)