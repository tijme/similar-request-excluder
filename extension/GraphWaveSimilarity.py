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
import re
import hashlib

class GraphWaveSimilarity:
    """The GraphWaveHttpListener listens to all spider packages flowing through Burp Suite.

    Attributes:
        tags_regex (obj): A regular expression that helps to extract HTML tags.
        classes_regex (obj): A regular expression that helps to extract HTML classes.
        structural_cache dict(obj): A key/value cache for HTML structures.
        style_cache dict(obj): A key/value cache for HTML classes.

    """

    tags_regex = re.compile("<([a-zA-Z0-9]+)(([^<>])+)?>")

    classes_regex = re.compile("class=(['\"`])(.+?)\1")

    structural_cache = {}

    style_cache = {}

    @staticmethod
    def getJaccardSimilarity(set1, set2):
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

    @staticmethod
    def getStructuralSimilarity(document1, document2):
        """Get the structural similarity between two documents.

        Args:
            document1 (str): The first document to measure.
            document2 (str): The second document to measure.

        Returns:
            (float): The structural similarity between the two documents.

        """

        # SET 1
        hash_object1 = hashlib.md5(document1.encode('utf-8'))
        hash_str1 = hash_object1.hexdigest()

        if hash_str1 in GraphWaveSimilarity.structural_cache.keys():
            tags1 = GraphWaveSimilarity.structural_cache[hash_str1]
        else:
            tags1 = GraphWaveSimilarity.getTagsFromDocument(document1.encode('utf-8'))
            GraphWaveSimilarity.structural_cache[hash_str1] = tags1

        # SET 2
        hash_object2 = hashlib.md5(document2.encode('utf-8'))
        hash_str2 = hash_object2.hexdigest()

        if hash_str2 in GraphWaveSimilarity.structural_cache.keys():
            tags2 = GraphWaveSimilarity.structural_cache[hash_str2]
        else:
            tags2 = GraphWaveSimilarity.getTagsFromDocument(document2.encode('utf-8'))
            GraphWaveSimilarity.structural_cache[hash_str2] = tags2

        diff = difflib.SequenceMatcher()

        diff.set_seq1(tags1)
        diff.set_seq2(tags2)

        return diff.real_quick_ratio()

    @staticmethod
    def getStyleSimilarity(document1, document2):
        """Get the style similarity between two documents.

        Args:
            document1 (str): The first document to measure.
            document2 (str): The second document to measure.

        Returns:
            (float): The style similarity between the two documents.

        """

        # SET 1
        hash_object1 = hashlib.md5(document1.encode('utf-8'))
        hash_str1 = hash_object1.hexdigest()

        if hash_str1 in GraphWaveSimilarity.style_cache.keys():
            classes_page1 = GraphWaveSimilarity.style_cache[hash_str1]
        else:
            GraphWaveSimilarity.style_cache[hash_str1] = GraphWaveSimilarity.getClassesFromDocument(document1)
            classes_page1 = GraphWaveSimilarity.style_cache[hash_str1]

        # SET 2
        hash_object2 = hashlib.md5(document2.encode('utf-8'))
        hash_str2 = hash_object2.hexdigest()

        if hash_str2 in GraphWaveSimilarity.style_cache.keys():
            classes_page2 = GraphWaveSimilarity.style_cache[hash_str2]
        else:
            GraphWaveSimilarity.style_cache[hash_str2] = GraphWaveSimilarity.getClassesFromDocument(document2)
            classes_page2 = GraphWaveSimilarity.style_cache[hash_str2]

        return GraphWaveSimilarity.getJaccardSimilarity(classes_page1, classes_page2)

    @staticmethod
    def getTagsFromDocument(document):
        """Get the HTML tags from a document.

        Args:
            document (str): The document to get HTML tags from.

        Returns:
            list(str): The tags/elements in the document.

        """

        results = re.findall(GraphWaveSimilarity.tags_regex, document)
        return list(results)

    @staticmethod
    def getClassesFromDocument(document):
        """Get the HTML style classes from a document.

        Args:
            document (str): The document to get HTML style classes from.

        Returns:
            set(str): The style classes in the document.

        """

        style_class_strings = re.findall(GraphWaveSimilarity.classes_regex, document)

        result = set()

        for style_class_string in style_class_strings:
            for style_class in style_class_string.split():
                result.add(style_class)

        return result
