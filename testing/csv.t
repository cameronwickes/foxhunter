#!/usr/bin/env python3

import os
import shutil
import unittest
from simpletap.fox import fox


class TestCSV(unittest.TestCase):
    def setUp(self):
        self.expected = os.path.join(fox.getProfiles(), "expected")
        self.outputDir = os.path.join(fox.getProfiles(), "outputCSV")

    def testDumpedAddons(self):
        with open(os.path.join(self.outputDir, "addons.csv")) as actualOutput:
            with open(os.path.join(self.expected, "addons.csv")) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedExtensions(self):
        with open(os.path.join(self.outputDir, "extensions.csv")) as actualOutput:
            with open(os.path.join(self.expected, "extensions.csv")) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedCookies(self):
        with open(os.path.join(self.outputDir, "cookies.csv")) as actualOutput:
            with open(os.path.join(self.expected, "cookies.csv")) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedFormHistory(self):
        with open(os.path.join(self.outputDir, "formHistory.csv")) as actualOutput:
            with open(os.path.join(self.expected, "formHistory.csv")) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedCertificates(self):
        with open(os.path.join(self.outputDir, "certificates.csv")) as actualOutput:
            with open(
                os.path.join(self.expected, "certificates.csv")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedLogins(self):
        with open(os.path.join(self.outputDir, "logins.csv")) as actualOutput:
            with open(
                os.path.join(self.expected, "logins.csv")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedAddons(self):
        with open(os.path.join(self.outputDir, "analysedAddons.csv")) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedAddons.csv")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedExtensions(self):
        with open(
            os.path.join(self.outputDir, "analysedExtensions.csv")
        ) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedExtensions.csv")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedCookies(self):
        with open(os.path.join(self.outputDir, "analysedCookies.csv")) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedCookies.csv")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedFormHistory(self):
        with open(
            os.path.join(self.outputDir, "analysedFormHistory.csv")
        ) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedFormHistory.csv")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedCertificates(self):
        with open(
            os.path.join(self.outputDir, "analysedCertificates.csv")
        ) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedCertificates.csv")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedLogins(self):
        with open(
            os.path.join(self.outputDir, "analysedLogins.csv")
        ) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedLogins.csv")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

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
