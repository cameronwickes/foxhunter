#!/usr/bin/env python3

import os
import shutil
import unittest
from simpletap.fox import fox


class TestJSON(unittest.TestCase):
    def setUp(self):
        self.expected = os.path.join(fox.getProfiles(), "expected")
        self.outputDir = os.path.join(fox.getProfiles(), "outputJSON")

    def testDumpedAddons(self):
        with open(os.path.join(self.outputDir, "addons.json")) as actualOutput:
            with open(os.path.join(self.expected, "addons.json")) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedExtensions(self):
        with open(os.path.join(self.outputDir, "extensions.json")) as actualOutput:
            with open(os.path.join(self.expected, "extensions.json")) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedCookies(self):
        with open(os.path.join(self.outputDir, "cookies.json")) as actualOutput:
            with open(os.path.join(self.expected, "cookies.json")) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedFormHistory(self):
        with open(os.path.join(self.outputDir, "formHistory.json")) as actualOutput:
            with open(
                os.path.join(self.expected, "formHistory.json")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedCertificates(self):
        with open(os.path.join(self.outputDir, "certificates.json")) as actualOutput:
            with open(
                os.path.join(self.expected, "certificates.json")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedLogins(self):
        with open(os.path.join(self.outputDir, "logins.json")) as actualOutput:
            with open(os.path.join(self.expected, "logins.json")) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedURLClickthroughs(self):
        with open(
            os.path.join(self.outputDir, "urlSearchClickthroughs.json")
        ) as actualOutput:
            with open(
                os.path.join(self.expected, "urlSearchClickthroughs.json")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedDownloads(self):
        with open(os.path.join(self.outputDir, "downloadHistory.json")) as actualOutput:
            with open(
                os.path.join(self.expected, "downloadHistory.json")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedBookmarks(self):
        with open(os.path.join(self.outputDir, "bookmarks.json")) as actualOutput:
            with open(os.path.join(self.expected, "bookmarks.json")) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testDumpedBrowsingHistory(self):
        with open(os.path.join(self.outputDir, "browsingHistory.json")) as actualOutput:
            with open(
                os.path.join(self.expected, "browsingHistory.json")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedAddons(self):
        with open(os.path.join(self.outputDir, "analysedAddons.json")) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedAddons.json")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedExtensions(self):
        with open(
            os.path.join(self.outputDir, "analysedExtensions.json")
        ) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedExtensions.json")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedCookies(self):
        with open(os.path.join(self.outputDir, "analysedCookies.json")) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedCookies.json")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedFormHistory(self):
        with open(
            os.path.join(self.outputDir, "analysedFormHistory.json")
        ) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedFormHistory.json")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedCertificates(self):
        with open(
            os.path.join(self.outputDir, "analysedCertificates.json")
        ) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedCertificates.json")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedLogins(self):
        with open(os.path.join(self.outputDir, "analysedLogins.json")) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedLogins.json")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedURLClickthroughs(self):
        with open(
            os.path.join(self.outputDir, "analysedUrlSearchClickthroughs.json")
        ) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedUrlSearchClickthroughs.json")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedDownloads(self):
        with open(
            os.path.join(self.outputDir, "analysedDownloads.json")
        ) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedDownloads.json")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()

    def testAnalysedBookmarks(self):
        with open(
            os.path.join(self.outputDir, "analysedBookmarks.json")
        ) as actualOutput:
            with open(
                os.path.join(self.expected, "analysedBookmarks.json")
            ) as expectedOutput:
                assert actualOutput.readlines() == expectedOutput.readlines()


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
