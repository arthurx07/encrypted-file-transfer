#!/bin/env python
# don't know??
from time import sleep
from alive_progress import alive_bar

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
print(mylist[0])
# print(type(mylist))
# print(len(mylist))
# results = [f() for f in mylist]

# for i in tqdm(mylist):
#     i()
#     sleep(3)

with alive_bar(3) as bar:
    for i in range(3):

        if i and i % 300 == 0:
            print('cool')
        bar()

print(a)
