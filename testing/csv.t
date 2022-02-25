#!/usr/bin/env python3

import os
import shutil
import unittest
from simpletap.fox import fox


class TestCSV(unittest.TestCase):
    def setUp(self):
        self.profile = os.path.join(fox.getProfiles(), "profile")
        self.profileWithPassword = os.path.join(fox.getProfiles(), "profilePassword")
        self.expected = os.path.join(fox.getProfiles(), "expected")
        self.password = fox.getPassword()
        self.outputDir = os.path.join(fox.getProfiles(), "outputCSV")
        

    def testDumpedAddons(self):
        with open(os.path.join(self.outputDir, "addons.csv")) as actualOutput:
            with open(os.path.join(self.expected, "addons.csv")) as expectedOutput:
                assert(actualOutput.readlines() == expectedOutput.readlines())

    def testDumpedExtensions(self):
        with open(os.path.join(self.outputDir, "extensions.csv")) as actualOutput:
            with open(os.path.join(self.expected, "extensions.csv")) as expectedOutput:
                assert(actualOutput.readlines() == expectedOutput.readlines())

    
    def testAnalysedAddons(self):
        with open(os.path.join(self.outputDir, "analysedAddons.csv")) as actualOutput:
            with open(os.path.join(self.expected, "analysedAddons.csv")) as expectedOutput:
                assert(actualOutput.readlines() == expectedOutput.readlines())

    def testAnalysedExtensions(self):
        with open(os.path.join(self.outputDir, "analysedExtensions.csv")) as actualOutput:
            with open(os.path.join(self.expected, "analysedExtensions.csv")) as expectedOutput:
                assert(actualOutput.readlines() == expectedOutput.readlines())
    



if __name__ == "__main__":
    from simpletap import TAPTestRunner

    profile = os.path.join(fox.getProfiles(), "profile")
    outputDir = os.path.join(fox.getProfiles(), "outputCSV")
    
    if os.path.isdir(outputDir):
        shutil.rmtree(outputDir)
    os.mkdir(outputDir)

    cmd = fox.getScript() + ["-p", profile, "-oC", outputDir, "-A"]
    _ = fox.run(cmd, workdir=fox.getProfiles())


    unittest.main(testRunner=TAPTestRunner(buffer=True), exit=False)

    shutil.rmtree(outputDir)


   