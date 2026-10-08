"""
indexer module
--------------
Code parsing, dependency & call graphs, embeddings/retrieval, and incremental index caching.
"""

from indexer.embeddings import CodeChunk, retrieve
from indexer.graph import CodeGraph
from indexer.index import RepoIndex, get_repo_index
from indexer.parser import ParsedFile, SymbolRecord, parse_source_file

__all__ = [
    "CodeChunk",
    "CodeGraph",
    "ParsedFile",
    "RepoIndex",
    "SymbolRecord",
    "get_repo_index",
    "parse_source_file",
    "retrieve",
]
