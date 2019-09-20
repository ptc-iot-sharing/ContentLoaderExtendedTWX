//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package com.thingworx.extensions.http;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

public class ArgumentValidator {
    public ArgumentValidator() {
    }

    private static final void throwValueIsNullException(String message) {
        if (message == null) {
            throw new NullPointerException("value=null && message=null");
        } else {
            throw new NullPointerException(message);
        }
    }

    private static final <T> void throwValueIsEmptyException(String message) {
        if (message == null) {
            throw new IllegalArgumentException("value=empty && message=null");
        } else {
            throw new IllegalArgumentException(message);
        }
    }

    /** @deprecated */
    @Deprecated
    public static Object checkNotNull(Object obj, String message) {
        return validateNotNull(obj, message);
    }

    /** @deprecated */
    @Deprecated
    public static String checkNotBlank(String string, String message) throws IllegalArgumentException {
        if (StringUtilities.isBlank(string)) {
            throw new IllegalArgumentException(message);
        } else {
            return string;
        }
    }

    /** @deprecated */
    @Deprecated
    public static boolean checkBothNotSetOrBothSet(String string1, String string2) {
        if (StringUtilities.isNullOrEmpty(string1) && StringUtilities.isNullOrEmpty(string2)) {
            return true;
        } else {
            return !StringUtilities.isNullOrEmpty(string1) && !StringUtilities.isNullOrEmpty(string2);
        }
    }

    public static <T> T validateNotNull(T value, String message) {
        if (value == null) {
            throwValueIsNullException(message);
        }

        return value;
    }

    public static String validateNotNullOrEmpty(String value, String message) {
        validateNotNull(value, message);
        if (0 == value.length()) {
            throwValueIsEmptyException(message);
        }

        return value;
    }

    public static <T extends Iterable<?>> T validateNotNullOrEmpty(T value, String message) {
        validateNotNull(value, message);
        Iterator<?> iterator = value.iterator();
        if (!iterator.hasNext()) {
            throwValueIsEmptyException(message);
        }

        return value;
    }

    public static <T extends Collection<?>> T validateNotNullOrEmpty(T value, String message) {
        validateNotNull(value, message);
        if (value.isEmpty()) {
            throwValueIsEmptyException(message);
        }

        return value;
    }

    public static <T extends Map<?, ?>> T validateNotNullOrEmpty(T value, String message) {
        validateNotNull(value, message);
        if (value.isEmpty()) {
            throwValueIsEmptyException(message);
        }

        return value;
    }

    public static <T> T[] validateNotNullOrEmpty(T[] value, String message) {
        validateNotNull(value, message);
        if (0 == value.length) {
            throwValueIsEmptyException(message);
        }

        return value;
    }

    public static <T> T validateNotNullOrEmpty(T value, String message) {
        if (value instanceof String) {
            validateNotNullOrEmpty((String)value, message);
        } else if (value instanceof Collection) {
            validateNotNullOrEmpty((Collection)value, message);
        } else if (value instanceof Map) {
            validateNotNullOrEmpty((Map)value, message);
        } else if (value instanceof Iterable) {
            validateNotNullOrEmpty((Iterable)value, message);
        } else {
            validateNotNull(value, message);
            if (value.getClass().isArray() && 0 == Array.getLength(value)) {
                throwValueIsEmptyException(message);
            }
        }

        return value;
    }
}
