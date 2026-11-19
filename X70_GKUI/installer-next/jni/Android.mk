LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := x70-apk-installer
LOCAL_SRC_FILES := install.c
LOCAL_CFLAGS := -std=c99 -Wall -Wextra -Werror
include $(BUILD_EXECUTABLE)
