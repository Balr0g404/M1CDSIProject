#!/usr/bin/python3
#coding: utf-8

import matplotlib.pyplot as plt
import tensorflow as tf
import tensorflow_datasets as tfds
import numpy as np
import sys
import os
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

example_text = "Ceci est un premier test"

tokenizer = tfds.features.text.Tokenizer()
vocabulary_set = set()
for text_tensor, _ in all_labeled_data:
  some_tokens = tokenizer.tokenize(text_tensor.numpy())
  vocabulary_set.update(some_tokens)

encoder = tfds.features.text.TokenTextEncoder(vocabulary_set)
encoded_example = encoder.encode(example_text)
print(encoded_example)
