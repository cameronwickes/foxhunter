#!/usr/bin/env python3

import os
import shutil
import unittest
from simpletap.fox import fox


class TestJSON(unittest.TestCase):
    def setUp(self):
        self.profile = os.path.join(fox.getProfiles(), "profile")
        self.profileWithPassword = os.path.join(fox.getProfiles(), "profilePassword")
        self.expected = os.path.join(fox.getProfiles(), "expected")
        self.password = fox.getPassword()
        self.outputDir = os.path.join(fox.getProfiles(), "outputJSON")
        
    def testDumpedAddons(self):
        with open(os.path.join(self.outputDir, "addons.json")) as actualOutput:
            with open(os.path.join(self.expected, "addons.json")) as expectedOutput:
                assert(actualOutput.readlines() == expectedOutput.readlines())

    def testDumpedExtensions(self):
        with open(os.path.join(self.outputDir, "extensions.json")) as actualOutput:
            with open(os.path.join(self.expected, "extensions.json")) as expectedOutput:
                assert(actualOutput.readlines() == expectedOutput.readlines())

    def testDumpedExtensions(self):
        with open(os.path.join(self.outputDir, "cookies.json")) as actualOutput:
            with open(os.path.join(self.expected, "cookies.json")) as expectedOutput:
                assert(actualOutput.readlines() == expectedOutput.readlines())

    
    def testAnalysedAddons(self):
        with open(os.path.join(self.outputDir, "analysedAddons.json")) as actualOutput:
            with open(os.path.join(self.expected, "analysedAddons.json")) as expectedOutput:
                assert(actualOutput.readlines() == expectedOutput.readlines())

    def testAnalysedExtensions(self):
        with open(os.path.join(self.outputDir, "analysedExtensions.json")) as actualOutput:
            with open(os.path.join(self.expected, "analysedExtensions.json")) as expectedOutput:
                assert(actualOutput.readlines() == expectedOutput.readlines())

    def testAnalysedCookies(self):
        with open(os.path.join(self.outputDir, "analysedCookies.json")) as actualOutput:
            with open(os.path.join(self.expected, "analysedCookies.json")) as expectedOutput:
                assert(actualOutput.readlines() == expectedOutput.readlines())


if __name__ == "__main__":
    from simpletap import TAPTestRunner

    profile = os.path.join(fox.getProfiles(), "profile")
    outputDir = os.path.join(fox.getProfiles(), "outputJSON")
    
    if os.path.isdir(outputDir):
        shutil.rmtree(outputDir)
    os.mkdir(outputDir)

    cmd = fox.getScript() + ["-p", profile, "-oJ", outputDir, "-A"]
    _ = fox.run(cmd, workdir=fox.getProfiles())

    unittest.main(testRunner=TAPTestRunner(buffer=True), exit=False)

    shutil.rmtree(outputDir)


   