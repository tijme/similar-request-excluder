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

class GraphWaveProperty:
    """A GraphWaveProperty is a characteristic of a response (e.g. a URL scheme or query)."""

    def __init__(self, key, weight, value):
        """Construct the GraphWaveProperty.

        Args:
            key (str): The name/key of the property.
            weight (float): The amount of points the property represents.
            value (str): The value that should match to get the points.

        """

        self.key = key
        self.weight = weight
        self.value = value

    def __str__(self):
        """The string representation of the property.

        Returns:
            str: The string representation of this class.

        """

        return self.key + "[" + str(self.weight) + "]=" + str(self.value)

    def __repr__(self):
        """The representation of the property.

        Returns:
            str: The representation of this class.

        """

        return str(self)

    def __hash__(self):
        """The hash representation of the property.

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
