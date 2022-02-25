import os
import sys
import re
import datetime
import tempfile
from subprocess import run, CalledProcessError, PIPE, STDOUT


class Test:
    def __init__(self):
        self.testDirectory = os.path.realpath(os.path.dirname(os.path.dirname(__file__)))
        self.interpreter = "python3"

        self.checkInterpreter()

    def checkInterpreter(self):
        out = run([self.interpreter, "--version"], capture_output=True)

        try:
            major, minor, _ = out.stdout.decode("utf-8").strip().split(" ")[1].split(".")
            valid_version = (int(major) == 3) & (int(minor) >= 10)
        except (ValueError, IndexError, TypeError):
            raise Exception("Wrong Python Versioning ('python3 --version').")

        if not valid_version:
            raise Exception(f"{self.interpreter} binary has version {major}.{minor}. Version 3.10 or above is required.")

    def run(self, cmd, stdin=None, stderr=STDOUT, workdir=None):
        if stderr == sys.stderr:
            with tempfile.NamedTemporaryFile(mode="w+t") as err:
                try:
                    p = run(cmd, check=True, encoding="utf8", cwd=workdir,
                            input=stdin, stdout=PIPE, stderr=err)
                except CalledProcessError as e:
                    if e.returncode:
                        err.flush()
                        err.seek(0)
                        sys.stderr.write(err.read())
                    raise

                else:
                    return p.stdout
        else:
            p = run(cmd, check=True, encoding="utf8", cwd=workdir,
                    input=stdin, stdout=PIPE, stderr=stderr)

            return p.stdout

    def runError(self, cmd, returncode, stdin=None, stderr=STDOUT, workdir=None):
        try:
            output = self.run(cmd, stdin=stdin, stderr=stderr, workdir=workdir)
        except CalledProcessError as e:
            if e.returncode != returncode:
                raise ValueError("Expected exit code {} but saw {}".format(returncode, e.returncode))
            else:
                output = e.stdout

        return output

    def getPassword(self):
        with open(os.path.join(self.getProfiles(), "masterPassword")) as masterFile:
            return masterFile.read()

    def getScript(self):
        return [self.interpreter, "{}/../foxhunter.py".format(self.testDirectory)]

    def getProfiles(self):
        return os.path.join(self.testDirectory, "data")

    def getDirectoryData(self, subDirectory, target):
        with open(os.path.join(self.get_test_data(), subDirectory, "{}.{}".format(target, subDirectory[:-1]))) as subDirectoryFile:
            return subDirectoryFile.read()

    def getOutputData(self, target):
        return self.getDirectoryData("outputs", target)

    def removePassword(self, output):
        return output.replace(os.path.join(self.testDirectory, ''), '')

    def grep(self, pattern, output, context=0):
        r = re.compile(pattern)
        lines = output.split('\n')

        acc = []
        for i in range(len(lines)):
            if r.search(lines[i]):
                acc.extend(lines[i-context:1+i+context])

        return '\n'.join(acc) + '\n'


fox = Test()

if __name__ == "__main__":
    pass

