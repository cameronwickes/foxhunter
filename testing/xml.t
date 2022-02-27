#!/usr/bin/env python3

import os
import shutil
import unittest
from simpletap.fox import fox


class TestXML(unittest.TestCase):
    def setUp(self):
        self.profile = os.path.join(fox.getProfiles(), "profile")
        self.profileWithPassword = os.path.join(fox.getProfiles(), "profilePassword")
        self.expected = os.path.join(fox.getProfiles(), "expected")
        self.password = fox.getPassword()
        self.outputDir = os.path.join(fox.getProfiles(), "outputXML")
        

    def testDumpedAddons(self):
        with open(os.path.join(self.outputDir, "addons.xml")) as actualOutput:
            with open(os.path.join(self.expected, "addons.xml")) as expectedOutput:
                assert(actualOutput.readlines() == expectedOutput.readlines())

    def testDumpedExtensions(self):
        with open(os.path.join(self.outputDir, "extensions.xml")) as actualOutput:
            with open(os.path.join(self.expected, "extensions.xml")) as expectedOutput:
                assert(actualOutput.readlines() == expectedOutput.readlines())

    def testDumpedCookies(self):
        with open(os.path.join(self.outputDir, "cookies.xml")) as actualOutput:
            with open(os.path.join(self.expected, "cookies.xml")) as expectedOutput:
                assert(actualOutput.readlines() == expectedOutput.readlines())

    def testDumpedFormHistory(self):
        with open(os.path.join(self.outputDir, "formHistory.xml")) as actualOutput:
            with open(os.path.join(self.expected, "formHistory.xml")) as expectedOutput:
                assert(actualOutput.readlines() == expectedOutput.readlines())

    def testAnalysedAddons(self):
        with open(os.path.join(self.outputDir, "analysedAddons.xml")) as actualOutput:
            with open(os.path.join(self.expected, "analysedAddons.xml")) as expectedOutput:
                assert(actualOutput.readlines() == expectedOutput.readlines())

    def testAnalysedExtensions(self):
        with open(os.path.join(self.outputDir, "analysedExtensions.xml")) as actualOutput:
            with open(os.path.join(self.expected, "analysedExtensions.xml")) as expectedOutput:
                assert(actualOutput.readlines() == expectedOutput.readlines())

    def testAnalysedCookies(self):
        with open(os.path.join(self.outputDir, "analysedCookies.xml")) as actualOutput:
            with open(os.path.join(self.expected, "analysedCookies.xml")) as expectedOutput:
                assert(actualOutput.readlines() == expectedOutput.readlines())
    
    def testAnalysedFormHistory(self):
        with open(os.path.join(self.outputDir, "analysedFormHistory.xml")) as actualOutput:
            with open(os.path.join(self.expected, "analysedFormHistory.xml")) as expectedOutput:
                print(actualOutput.readlines(), expectedOutput.readlines())
                assert(actualOutput.readlines() == expectedOutput.readlines())
    



if __name__ == "__main__":
    from simpletap import TAPTestRunner

    profile = os.path.join(fox.getProfiles(), "profile")
    outputDir = os.path.join(fox.getProfiles(), "outputXML")
    
    if os.path.isdir(outputDir):
        shutil.rmtree(outputDir)
    os.mkdir(outputDir)

    cmd = fox.getScript() + ["-p", profile, "-oX", outputDir, "-A"]
    _ = fox.run(cmd, workdir=fox.getProfiles())

    unittest.main(testRunner=TAPTestRunner(buffer=True), exit=False)

    shutil.rmtree(outputDir)


   