#!/usr/bin/env python3

import os
import shutil
import unittest
from simpletap.fox import fox
from glob import glob
import hashlib
import collections


class TestDiagrams(unittest.TestCase):
    def setUp(self):
        self.expected = os.path.join(fox.getProfiles(), "expected/diagrams")
        self.outputDir = os.path.join(fox.getProfiles(), "outputDiagrams/diagrams")

    def testDumpedDiagrams(self):
        expectedDiagramFilenames = [os.path.basename(x) for x in glob(self.expected + "/*")]
        actualDiagramFilenames = [os.path.basename(x) for x in glob(self.outputDir + "/*")]
        
        assert collections.Counter(actualDiagramFilenames) == collections.Counter(expectedDiagramFilenames)


if __name__ == "__main__":
    from simpletap import TAPTestRunner

    profile = os.path.join(fox.getProfiles(), "profile")
    outputDir = os.path.join(fox.getProfiles(), "outputDiagrams")

    if os.path.isdir(outputDir):
        shutil.rmtree(outputDir)
    os.mkdir(outputDir)

    cmd = fox.getScript() + ["-p", profile, "-oC", outputDir, "-A"]
    _ = fox.run(cmd, workdir=fox.getProfiles())

    unittest.main(testRunner=TAPTestRunner(buffer=True), exit=False)

    shutil.rmtree(outputDir)
