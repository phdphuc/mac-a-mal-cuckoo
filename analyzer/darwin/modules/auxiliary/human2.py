# It's possible to use Quartz library only instead of using pyautogui (https://github.com/asweigart/pyautogui/blob/319d401bcec7341263e5c16acb6651534332d9a9/pyautogui/_pyautogui_osx.py)
# Pham

import random
import logging
import time
from threading import Thread
import Quartz.CoreGraphics as CG
from Quartz import kCGWindowListOptionOnScreenOnly, kCGNullWindowID, CGWindowListCopyWindowInfo, CGEventCreateMouseEvent, kCGEventMouseMoved
from AppKit import *
import pyautogui

workspace = NSWorkspace.sharedWorkspace()
rect = NSScreen.mainScreen().frame()
width = int(rect.size.width)

def click_mouse(x,y):
    #create the event
    move = CG.CGEventCreateMouseEvent(None, CG.kCGEventMouseMoved, (x, y), 0)
    #send the event
    CG.CGEventPost(CG.kCGHIDEventTap, move)
    # Mouse down.
    down = CG.CGEventCreateMouseEvent(None, CG.kCGEventLeftMouseDown, (x, y), CG.kCGMouseButtonLeft)
    # Mouse up.
    up = CG.CGEventCreateMouseEvent(None, CG.kCGEventLeftMouseUp, (x, y), CG.kCGMouseButtonLeft)
    #send the events
    CG.CGEventPost(CG.kCGHIDEventTap, down)
    time.sleep(0.05)
    CG.CGEventPost(CG.kCGHIDEventTap, up)

while True:
    activeApps = workspace.runningApplications()
    for app in activeApps:
        options = kCGWindowListOptionOnScreenOnly
        windowList = CGWindowListCopyWindowInfo(options, kCGNullWindowID)
        for window in windowList:
            if window['kCGWindowOwnerName'] == "SecurityAgent":
                pyautogui.typewrite('123456\n', interval=0.05)  # Enter admin password then enter, TODO: use cuckoo admin password option
                break
        break
    buttons = ['continue.png', 'agree.png', 'install.png', 'close.png']
    for button in buttons:
        try:
            buttonx,buttony = pyautogui.locateCenterOnScreen(button, grayscale=True)
            print "Detected defined button at: ", buttonx/2, buttony/2 #Assume we're under Retina monitor
            click_mouse(buttonx/2, buttony/2) 
        except TypeError:
            continue
    time.sleep(1)