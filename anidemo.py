#!/bin/env python
from time import sleep
from tqdm import tqdm

a = 0
def function1():
    global a
    a += 1
def function2():
    global a
    a += 1
def function3():
    global a
    a += 1

mylist = [ function1, function2, function3 ]
# print(type(mylist))
# print(len(mylist))
# results = [f() for f in mylist]

for i in tqdm(mylist):
    i()
    sleep(3)

print(a)
