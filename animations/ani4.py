import sys
import threading
import time


# Here is an example of the process function:


def the_process_function():
    n = 20
    for i in range(n):
        time.sleep(1)
        sys.stdout.write(
            "\r"
            + "loading...  process "
            + str(i)
            + "/"
            + str(n)
            + " "
            + "{:.2f}".format(i / n * 100)
            + "%"
        )
        sys.stdout.flush()
    sys.stdout.write("\r" + "loading... finished               \n")


def animated_loading():
    chars = "/—\|"
    for char in chars:
        sys.stdout.write("\r" + "loading..." + char)
        time.sleep(0.1)
        sys.stdout.flush()


the_process = threading.Thread(name="process", target=the_process_function)
the_process.start()
while the_process.isAlive():
    animated_loading()
