# -*- coding: utf-8 -*-

# MIT License
#
# Copyright (c) 2018 Tijme Gommers
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os

class ExtensionDetails:
    """Global variables for the extension.

    Attributes:
        TITLE (str): The title of the extension.
        VERSION (str): The (semantic) version of the extension.
        DEBUG (bool): Messages will be logged to Burp Suite if True.
        STATUS_LOADING (str): State for when the extension is loading (initial state).
        STATUS_DISABLED (str): State for when the extension is disabled (state after loading).
        STATUS_ENABLED (str): State for when the extension is enabled by the user.

    """

    TITLE = "GraphWave"

    VERSION = "Unknown"

    DEBUG = False

    STATUS_LOADING = "loading"
    STATUS_DISABLED = "disabled"
    STATUS_ENABLED = "enabled"

    @staticmethod
    def initialize():
        """Change the static variables if they need to be changed.

        Note:
            The version number should be loaded from the `.semver` file for example.

        """

        # Read version from .semver file if it exists
        try:
            path = os.path.dirname(os.path.abspath('__file__'))
            semver = open(path + "/../.semver", "r")
            ExtensionDetails.VERSION = semver.read().rstrip()
            semver.close()
        except:
            pass
