#!/usr/bin/env python3

import os
import shutil
import unittest
from simpletap.fox import fox


class TestLogins(unittest.TestCase):
    def setUp(self):
        self.profile = os.path.join(fox.getProfiles(), "profilePassword")
        self.expected = os.path.join(fox.getProfiles(), "expected")
        self.outputDir = os.path.join(fox.getProfiles(), "outputLogins")
        self.password = fox.getPassword()

    def testPasswordAuthentication(self):
        if os.path.isdir(self.outputDir):
            shutil.rmtree(self.outputDir)
        os.mkdir(self.outputDir)

        cmd = fox.getScript() + [
            "-p",
            self.profile,
            "-oC",
            self.outputDir,
            "-oJ",
            self.outputDir,
            "-oX",
            self.outputDir,
        ]
        _ = fox.run(
            cmd,
            workdir=fox.getProfiles(),
            stdin="1\n{}\n1\n{}\n".format("PasswordAuthFailure", self.password),
        )

        for fileType in ["csv", "json", "xml"]:
            with open(
                os.path.join(self.outputDir, "logins.{}".format(fileType))
            ) as actualOutput:
                with open(
                    os.path.join(self.expected, "logins.{}".format(fileType))
                ) as expectedOutput:
                    assert actualOutput.readlines() == expectedOutput.readlines()

        if os.path.isdir(self.outputDir):
            shutil.rmtree(outputDir)

    def testBruteForce(self):
        if os.path.isdir(self.outputDir):
            shutil.rmtree(self.outputDir)
        os.mkdir(self.outputDir)

        cmd = fox.getScript() + [
            "-p",
            self.profile,
            "-oC",
            self.outputDir,
            "-oJ",
            self.outputDir,
            "-oX",
            self.outputDir,
        ]
        _ = fox.run(
            cmd,
            workdir=fox.getProfiles(),
            stdin="2\n{}\n2\n{}".format(
                os.path.join(fox.getProfiles(), "wordlistWithoutPassword"),
                os.path.join(fox.getProfiles(), "wordlistWithPassword"),
            ),
        )

        for fileType in ["csv", "json", "xml"]:
            with open(
                os.path.join(self.outputDir, "logins.{}".format(fileType))
            ) as actualOutput:
                with open(
                    os.path.join(self.expected, "logins.{}".format(fileType))
                ) as expectedOutput:
                    assert actualOutput.readlines() == expectedOutput.readlines()

        if os.path.isdir(self.outputDir):
            shutil.rmtree(outputDir)

    def testGiveUp(self):
        if os.path.isdir(self.outputDir):
            shutil.rmtree(self.outputDir)
        os.mkdir(self.outputDir)

        cmd = fox.getScript() + [
            "-p",
            self.profile,
            "-oC",
            self.outputDir,
            "-oJ",
            self.outputDir,
            "-oX",
            self.outputDir,
        ]
        _ = fox.run(cmd, workdir=fox.getProfiles(), stdin="3\n")

        for fileType in ["csv", "json", "xml"]:
            with open(
                os.path.join(self.outputDir, "logins.{}".format(fileType))
            ) as actualOutput:
                with open(
                    os.path.join(self.expected, "loginsEncrypted.{}".format(fileType))
                ) as expectedOutput:
                    assert actualOutput.readlines() == expectedOutput.readlines()

        if os.path.isdir(self.outputDir):
            shutil.rmtree(outputDir)


if __name__ == "__main__":
    from simpletap import TAPTestRunner

    outputDir = os.path.join(fox.getProfiles(), "outputLogins")

    unittest.main(testRunner=TAPTestRunner(buffer=True), exit=False)

    if os.path.isdir(outputDir):
        shutil.rmtree(outputDir)
