TARGET := iphone:clang:latest:10.0
ARCHS = arm64
DEBUG = 0
INSTALL_TARGET_PROCESSES = 安馨办


include $(THEOS)/makefiles/common.mk

TWEAK_NAME = AXBBypassJailbreak

AXBBypassJailbreak_FILES = Tweak.x
AXBBypassJailbreak_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
