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

class GraphWaveDocumentParser:
    """A helper class for extracting certain characteristic from HTML documents."""

    def __init__(self, document):
        """Initialize the document parser with the given HTML document string.

        Args:
            document (str): The HTML document to parse.

        """

        self.document = document
        self.parsed = False

        self.is_in_element = False
        self.is_in_attribute = False
        self.is_in_class_attribute = False

        self.class_attributes = {}
        self.classes = []
        self.elements = {}
        self.element_index = 0

        self.attribute_quotes = ["\"", "'", "`"]
        self.attribute_quote = None

        self.parse()

    def addToIndex(self, arr, indx, char):
        """Append a certain character to an element on the given index.

        Args:
            arr (obj): The dict to add the char to.
            indx (int): The index to place the character on.
            char (str): The character to append.

        """

        try:
            arr[indx] += char
        except:
            arr[indx] = char

    def parse(self):
        """Parse the document by extracting tags and classes."""

        if self.parsed:
            return

        for character in self.document:
            if not self.is_in_element and character == "<":
                self.is_in_element = True

            if self.is_in_element:
                self.addToIndex(self.elements, self.element_index, character)

            if self.is_in_attribute and character == self.attribute_quote:
                self.is_in_attribute = False
                self.is_in_class_attribute = False
                self.attribute_quote = None
            else:
                if self.is_in_class_attribute:
                    self.addToIndex(self.class_attributes, self.element_index, character)

                if not self.is_in_attribute and self.is_in_element and character in self.attribute_quotes:
                    self.attribute_quote = character
                    self.is_in_attribute = True

                    if self.elements[self.element_index][-7:-2] == "class":
                        self.is_in_class_attribute = True

            if self.is_in_element and character == ">" and not self.is_in_attribute:
                self.is_in_element = False
                self.element_index += 1

        for class_attribute in self.class_attributes.values():
            if class_attribute:
                self.classes.extend(class_attribute.split(" "))

        self.parsed = True

    def getTags(self):
        """Return HTML elements/tags of the parsed document.

        Returns:
            list(str): The HTML elements/tags of the parsed document.

        """

        return self.elements.values()

    def getClasses(self):
        """Return CSS classes of the parsed document.

        Returns:
            list(str): The CSS classes of the parsed document.

        """

        return self.classes
