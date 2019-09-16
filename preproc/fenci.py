# -*- coding: utf-8 -*-
"""
juliet.py - Juliet Test Suite (https://samate.nist.gov/SRD/testsuite.php)
:Author: Verf
:Email: verf@protonmail.com
:License: MIT
"""
import re
import pickle
import zipfile
from concurrent import futures
from torchplp.utils.loader import loader_cc
from torchplp.utils.utils import download_file
from .models import Dataset
from .constants import JULIET_URL
from ..core import *


class Juliet(Dataset):def load(self, cwe: str) -> list:
        files = self._category[cwe]
        all_samples = self.tag_all_files(files, [f"-I{str(self._support)}"])
        return all_samples
      
      @staticmethod
    def tag_file(file: str, args: list) -> list:
        """extract function from file and tag it by it's name"""
        samples = list()
        ast = loader_cc(str(file), args)
        decl = [
            x for x in ast.walk()
            if x.is_definition and x.kind == 'FUNCTION_DECL'
        ]
        for node in decl:
            if 'main' in str(node.data):
                continue
            if str(node.data) == 'good':
                continue
            if len(list(node.walk())) < 6:
                continue
            label = 1 if 'bad' in str(node.data) else 0
            samples.append((node, label))
        return samples

    def tag_callback(self, r: Any) -> list:
        self.all_samples.extend(r.result())

    def tag_all_files(self, files, args):
        """tag all files"""
        self.all_samples = list()
        with futures.ProcessPoolExecutor() as pool:
            for file in files:
                res = pool.submit(self.tag_file, file, args)
                res.add_done_callback(self.tag_callback)
        return self.all_samples

    @staticmethod
    def iscwe(name: str) -> Union[None, str]:
        m = re.match(r'CWE\d{2,3}', name)
        return m.group() if m is not None else False
