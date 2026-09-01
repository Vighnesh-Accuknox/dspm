"""
Connector-independent classification pipeline.

    connector  ->  Record / TextBlob stream  ->  UnitClassifier  ->  findings

A connector only knows how to enumerate its units (tables, collections,
objects) and how to turn one unit into a stream of records or text blobs (see
records.py). Everything a DSPM vendor does *after* pattern matching - context
policy, record-level corroboration, column density verdicts, minimum counts,
adaptive sampling, aggregation - happens once, here, for every connector.
"""
from src.pipeline.classifier import UnitClassifier
from src.pipeline.records import Cell, Record, TextBlob, collapse_indices, document_record, flatten

__all__ = ["Cell", "Record", "TextBlob", "UnitClassifier", "collapse_indices", "document_record", "flatten"]
