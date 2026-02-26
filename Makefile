export THEOS_PACKAGE_SCHEME = rootless
ARCHS = arm64 arm64e
TARGET := iphone:clang:latest:15.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = PokerStarsSSLBypass

PokerStarsSSLBypass_FILES = Tweak.x
PokerStarsSSLBypass_CFLAGS = -fobjc-arc -Wno-unused-function -Wno-unused-variable
PokerStarsSSLBypass_FRAMEWORKS = Foundation Security UIKit WebKit
PokerStarsSSLBypass_LOGOS_DEFAULT_GENERATOR = internal

include $(THEOS_MAKE_PATH)/tweak.mk
