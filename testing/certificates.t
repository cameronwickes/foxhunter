#!/usr/bin/env python3

import os
import shutil
import unittest
from simpletap.fox import fox
from glob import glob
import hashlib
import collections


class TestCertificates(unittest.TestCase):
    def setUp(self):
        self.expected = os.path.join(fox.getProfiles(), "expected/certificates")
        self.outputDir = os.path.join(
            fox.getProfiles(), "outputCertificates/certificates"
        )

    def testDumpedCertificates(self):
        expectedCertificateFilenames = glob(self.expected + "/*")
        actualCertificateFilenames = glob(self.outputDir + "/*")
        expectedHashes = []
        actualHashes = []

        for filenames, hashList in [
            (expectedCertificateFilenames, expectedHashes),
            (actualCertificateFilenames, actualHashes),
        ]:
            for file in filenames:
                with open(file, "rb") as fileHandle:
                    hashList.append(hashlib.sha256(fileHandle.read()).hexdigest())

        assert collections.Counter(expectedHashes) == collections.Counter(actualHashes)


if __name__ == "__main__":
    from simpletap import TAPTestRunner

    profile = os.path.join(fox.getProfiles(), "profile")
    outputDir = os.path.join(fox.getProfiles(), "outputCertificates")

    if os.path.isdir(outputDir):
        shutil.rmtree(outputDir)
    os.mkdir(outputDir)

    cmd = fox.getScript() + ["-p", profile, "-oC", outputDir]
    _ = fox.run(cmd, workdir=fox.getProfiles())

    unittest.main(testRunner=TAPTestRunner(buffer=True), exit=False)

    shutil.rmtree(outputDir)
