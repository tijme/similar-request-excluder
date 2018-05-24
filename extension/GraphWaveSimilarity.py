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

import difflib
import hashlib

from GraphWaveDocumentParser import GraphWaveDocumentParser

class GraphWaveSimilarity:
    """The GraphWaveHttpListener listens to all spider packages flowing through Burp Suite.

    Attributes:
        cache dict(obj): A key/value cache for all kinds of slow functionality.

    """

    cache = {}

    def __init__(self, document1, document2):
        """Initialzie the similarityh measure class.

        Args:
            document1 (str): The first document to measure.
            document2 (str): The second document to measure.

        """

        self.document1 = document1.encode('utf-8')
        self.document2 = document2.encode('utf-8')

        self.parser1 = self.doCache("parser", self.getHashOf(self.document1), lambda : GraphWaveDocumentParser(self.document1))
        self.parser2 = self.doCache("parser", self.getHashOf(self.document2), lambda : GraphWaveDocumentParser(self.document2))

    def getHashOf(self, document):
        """Get the hash for dict indexes.

        Args:
            document (str): The document to hash.

        Returns:
            str: The hash of the given document.

        """

        hash_object = hashlib.md5(document)
        return hash_object.hexdigest()

    def doCache(self, store, key, callback):
        """Cache the given lambda in a store using the given key.

        Args:
            store (str): The cache store to use.
            key (str): The index key (usually a hash).
            callback (lambda): The callback containing the value.

        Returns:
            obj: The cached value of the callback function.

        """

        if not store in GraphWaveSimilarity.cache.keys():
            GraphWaveSimilarity.cache[store] = {}

        if not key in GraphWaveSimilarity.cache[store].keys():
            GraphWaveSimilarity.cache[store][key] = callback()

        return GraphWaveSimilarity.cache[store][key]

    def getStructuralSimilarity(self):
        """Get the structural similarity between two documents.

        Returns:
            (float): The structural similarity between the two documents.

        """

        tags1 = self.doCache("structural", self.getHashOf(self.document1), lambda : self.parser1.getTags())
        tags2 = self.doCache("structural", self.getHashOf(self.document2), lambda : self.parser2.getTags())

        diff = difflib.SequenceMatcher()

        diff.set_seq1(tags1)
        diff.set_seq2(tags2)

        return diff.real_quick_ratio()

    def getStyleSimilarity(self):
        """Get the style similarity between two documents.

        Returns:
            (float): The style similarity between the two documents.

        """

        classes_page1 = self.doCache("style", self.getHashOf(self.document1), lambda : self.parser1.getClasses())
        classes_page2 = self.doCache("style", self.getHashOf(self.document2), lambda : self.parser2.getClasses())

        return self.getJaccardSimilarity(classes_page1, classes_page2)

    def getJaccardSimilarity(self, set1, set2):
        """Get the Jaccard distance between two sets.

        Args:
            set1 (set): The first set to measure.
            set2 (set): The second set to measure.

        Returns:
            (float): The Jaccard distance between the two sets.

        """

        set1 = set(set1)
        set2 = set(set2)

        intersection = len(set1 & set2)

        if len(set1) == 0 and len(set2) == 0:
            return 1.0

        denominator = len(set1) + len(set2) - intersection
        return intersection / max(denominator, 0.000001)
