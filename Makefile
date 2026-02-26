ARCHS = arm64 arm64e
TARGET := iphone:clang:latest:15.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = PokerStarsSSLBypass

PokerStarsSSLBypass_FILES = Tweak.x
PokerStarsSSLBypass_CFLAGS = -fobjc-arc -Wno-unused-variable -Wno-deprecated-declarations
PokerStarsSSLBypass_FRAMEWORKS = Security UIKit Foundation WebKit
PokerStarsSSLBypass_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk
