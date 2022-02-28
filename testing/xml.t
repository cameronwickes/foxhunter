#!/usr/bin/env python3

import os
import shutil
import unittest
from simpletap.fox import fox


class TestXML(unittest.TestCase):
    def setUp(self):
        self.expected = os.path.join(fox.getProfiles(), "expected")
        self.outputDir = os.path.join(fox.getProfiles(), "outputXML")

    def testDumpedAddons(self):
        with open(os.path.join(self.outputDir, "addons.xml")) as actualOutput:
            with open(os.path.join(self.expected, "addons.xml")) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedExtensions(self):
        with open(os.path.join(self.outputDir, "extensions.xml")) as actualOutput:
            with open(os.path.join(self.expected, "extensions.xml")) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedCookies(self):
        with open(os.path.join(self.outputDir, "cookies.xml")) as actualOutput:
            with open(os.path.join(self.expected, "cookies.xml")) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedFormHistory(self):
        with open(os.path.join(self.outputDir, "formHistory.xml")) as actualOutput:
            with open(os.path.join(self.expected, "formHistory.xml")) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedCertificates(self):
        with open(os.path.join(self.outputDir, "certificates.xml")) as actualOutput:
            with open(
                os.path.join(self.expected, "certificates.xml")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedLogins(self):
        with open(os.path.join(self.outputDir, "logins.xml")) as actualOutput:
            with open(os.path.join(self.expected, "logins.xml")) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedURLClickthroughs(self):
        with open(
            os.path.join(self.outputDir, "urlSearchClickthroughs.xml")
        ) as actualOutput:
            with open(
                os.path.join(self.expected, "urlSearchClickthroughs.xml")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedDownloads(self):
        with open(os.path.join(self.outputDir, "downloadHistory.xml")) as actualOutput:
            with open(
                os.path.join(self.expected, "downloadHistory.xml")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedBookmarks(self):
        with open(os.path.join(self.outputDir, "bookmarks.xml")) as actualOutput:
            with open(os.path.join(self.expected, "bookmarks.xml")) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedBrowsingHistory(self):
        with open(os.path.join(self.outputDir, "browsingHistory.xml")) as actualOutput:
            with open(
                os.path.join(self.expected, "browsingHistory.xml")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedAddons(self):
        with open(os.path.join(self.outputDir, "analysedAddons.xml")) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedAddons.xml")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedExtensions(self):
        with open(
            os.path.join(self.outputDir, "analysedExtensions.xml")
        ) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedExtensions.xml")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedCookies(self):
        with open(os.path.join(self.outputDir, "analysedCookies.xml")) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedCookies.xml")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedFormHistory(self):
        with open(
            os.path.join(self.outputDir, "analysedFormHistory.xml")
        ) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedFormHistory.xml")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedCertificates(self):
        with open(
            os.path.join(self.outputDir, "analysedCertificates.xml")
        ) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedCertificates.xml")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedLogins(self):
        with open(os.path.join(self.outputDir, "analysedLogins.xml")) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedLogins.xml")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedURLClickthroughs(self):
        with open(
            os.path.join(self.outputDir, "analysedUrlSearchClickthroughs.xml")
        ) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedUrlSearchClickthroughs.xml")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedDownloads(self):
        with open(
            os.path.join(self.outputDir, "analysedDownloads.xml")
        ) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedDownloads.xml")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedBookmarks(self):
        with open(
            os.path.join(self.outputDir, "analysedBookmarks.xml")
        ) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedBookmarks.xml")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()


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
