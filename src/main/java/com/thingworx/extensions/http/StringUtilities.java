package com.thingworx.extensions.http;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

public class StringUtilities {

  public static boolean isNullOrEmpty(String s) {
    if (s == null) {
      return true;
    } else {
      return s.length() == 0;
    }
  }

  public static boolean isNonEmpty(String s) {
    if (s == null) {
      return false;
    } else {
      return s.length() > 0;
    }
  }

  public static String readFromStream(InputStream stream, boolean withClose)
      throws Exception {
    int length = 8192;
    StringBuilder buffer = new StringBuilder();
    InputStreamReader isr = new InputStreamReader(stream, StandardCharsets.UTF_8);
    Throwable var5 = null;

    try {
      BufferedReader in = new BufferedReader(isr, length);
      Throwable var7 = null;

      try {
        int ch;
        while ((ch = in.read()) > -1) {
          buffer.append((char) ch);
        }

        if (withClose) {
          try {
            in.close();
            stream.close();
          } catch (Exception ignored) {
          }
        }
      } catch (Throwable var34) {
        var7 = var34;
        throw var34;
      } finally {
        if (var7 != null) {
          try {
            in.close();
          } catch (Throwable var32) {
            var7.addSuppressed(var32);
          }
        } else {
          in.close();
        }
      }
    } catch (Throwable var36) {
      var5 = var36;
      throw var36;
    } finally {
      if (var5 != null) {
        try {
          isr.close();
        } catch (Throwable var31) {
          var5.addSuppressed(var31);
        }
      } else {
        isr.close();
      }
    }

    return buffer.toString();
  }

  public static boolean isBlank(String string) {
    if (isNullOrEmpty(string)) {
      return true;
    } else {
      for (int x = 0; x < string.length(); ++x) {
        if (!Character.isWhitespace(string.charAt(x))) {
          return false;
        }
      }

      return true;
    }
  }
}
