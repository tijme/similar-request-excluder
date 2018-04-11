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

from GraphWaveSimilarity import GraphWaveSimilarity

class GraphWaveResponse:
    """A GraphWaveResponse contains data from a processed Burp Suite message."""

    def __init__(self, url, html):
        """Construct the GraphWaveProperty.

        Args:
            url (str): The URL of the Burp Suite message.
            html (str): The response body of the Burp Suite message.

        """

        self.url = url
        self.html = html

    def __str__(self):
        """The string representation of the response.

        Returns:
            str: The string representation of this class.

        """

        return self.url

    def __repr__(self):
        """The representation of the response.

        Returns:
            str: The representation of this class.

        """

        return str(self)

    def __hash__(self):
        """The hash representation of the response.

        Returns:
            str: The hash representation of this class.

        """

        return hash(str(self))

    def __eq__(self, other):
        """Check if this class is equal to the given other class.

        Returns:
            bool: True if equal, False otherwise.

        """

        return str(self) == str(other)

    def __ne__(self, other):
        """Check if this class is not equal to the given other class.

        Returns:
            bool: True if not equal, False otherwise.

        """

        return str(self) != str(other)

    def getSimilarity(self, other):
        """Check if the given response is similar to this response.

        Returns:
            float: The Jaccard distance (similarity measure).

        """

        structural = GraphWaveSimilarity.getStructuralSimilarity(self.html, other.html)
        style = GraphWaveSimilarity.getStyleSimilarity(self.html, other.html)

        return (0.80 * structural) + (0.20 * style)
