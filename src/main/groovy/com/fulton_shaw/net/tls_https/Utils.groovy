package com.fulton_shaw.net.tls_https


import com.fulton_shaw.net.tls_https.annotations.Calculated
import com.fulton_shaw.net.tls_https.annotations.Length
import com.fulton_shaw.net.tls_https.annotations.Randomized
import com.fulton_shaw.net.tls_https.annotations.Timestamp
import com.fulton_shaw.net.tls_https.annotations.Typed
import com.fulton_shaw.net.tls_https.support.IntPack
import org.apache.commons.io.HexDump
import org.apache.commons.io.IOUtils

import javax.annotation.Nonnull
import java.lang.reflect.Array
import java.lang.reflect.Field
import java.lang.reflect.Modifier
import java.nio.charset.StandardCharsets
import java.util.concurrent.ThreadLocalRandom;


class Utils {

    static Socket connect(String host, int port) {
        return new Socket(host, port)
    }

    static <E extends Enum<E>> E enumOfValue(E[] values, int value) {
        for (E e : values) {
            if (e.value == value) {
                return e
            }
        }
        return null
    }

    static byte[] toBytes(@Nonnull Object o) {
        o.getProperties()
    }

    static String hexdump(byte[] data) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream(data.length * 4)
        HexDump.dump(data, 0, stream, 0)
        return stream.toString(StandardCharsets.UTF_8.name())
    }

    static byte fromTwoCharHex(char sHi, char sLo) {
        return (((sHi >= (char) 'a' && sHi <= (char) 'f') ? (sHi - (char) 'a' + 10) : ((sHi >= (char) 'A' && sHi <= (char) 'F') ? sHi - (char) 'A' + 10 : sHi - (char) '0')) << 4) | ((sLo >= (char) 'a' && sLo <= (char) 'f') ? (sLo - (char) 'a' + 10) : ((sLo >= (char) 'A' && sLo <= (char) 'F') ? sLo - (char) 'A' + 10 : sLo - (char) '0'))
    }

    static char toHexChar(int b) {
        return b >= 10 && b <= 16 ? ((char) 'a' + b - 10) : ((char) '0' + b)
    }

    static byte[] fromRawHexString(String s) {
//        010001fc0303de52501336e67ebd5b9924af1c65a2235bfae16d882286c7a07f7c29c73078ba20d8d8b910452fd670fc0315c39346c8cc1b4831df31fd402364cc9119413c172c00481302130313011304c02cc030cca9cca8c0adc02bc02fc0acc023c027c00ac014c009c013009dc09d009cc09c003d003c0035002f009fccaac09f009ec09e006b00670039003300ff0100016b00000012001000000d7777772e62616964752e636f6d000b000403000102000a000c000a001d0017001e00190018337400000010000e000c02683208687474702f312e31001600000017000000310000000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602002b0009080304030303020301002d00020101003300260024001d00202ac995cfd440523c314e81183ac4e113ae27d34ac5bd47bf9720fce470acd15e001500a600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
        if (s.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string length should be multiple of 2")
        }
        byte[] data = new byte[s.length() / 2]
        int j = 0
        for (int i = 0; i < data.length; ++i) {
            data[i] = fromTwoCharHex(s.charAt(j), s.charAt(j + 1))
//            println "data[i]=${data[i]}"
            j += 2
        }
        return data
    }

    static String toRawHexString(byte[] arr) {
        StringBuilder stringBuilder = new StringBuilder(arr.length * 2)
        for (int i = 0; i < arr.length; i++) {
            stringBuilder.append(toHexChar((arr[i] >> 4) & 0xf)).append(toHexChar(arr[i] & 0xf))
        }
        return stringBuilder.toString()
    }
}

class SerializeUtils {

    private static final ThreadLocal<byte[]> NUM_BUF = new ThreadLocal<byte[]>() {
        @Override
        protected byte[] initialValue() {
            return new byte[8]
        }
    }

    /**
     * length must be deterministic at runtime
     * @param clz
     * @param o
     * @return a value >= 0
     */
    static int getRuntimeLength(@Nonnull Object o) {
        def clz = o.getClass()
//        println "getRuntimeLength for ${o} ${clz.name}"
        if (o instanceof Class) {
            throw new IllegalArgumentException("class found")
        }
        if (clz.isArray()) {
            int sum = 0
            int len = Array.getLength(o)
            for (int i = 0; i < len; ++i) {
                sum += getRuntimeLength(Array.get(o, i))
            }
            return sum
        }
        if (clz == byte.class || clz == boolean.class || clz == Byte.class || clz == Boolean.class) {
            return 1
        } else if (clz == short.class || clz == Short.class) {
            return 2
        } else if (clz == int.class || clz == Integer.class) {
            return 4
        } else if (clz == long.class || clz == Long.class) {
            return 8
        } else {
            int sum = 0
            def fields = clz.getDeclaredFields()
            int n = fields.length
            for (int i = 0; i < n; i++) {
                def field = fields[i]
                if (!isUserDefinedInstanceField(field)) {
                    continue
                }

                // the Length annotation can be used to statically define the length
                def lengthAnnotation = field.getAnnotation(Length.class)
                if (lengthAnnotation != null && lengthAnnotation.value() != -1) {
                    sum += lengthAnnotation.value()
                } else {
                    field.setAccessible(true)
//                    println "getRuntimeLength for field ${field.name}"
                    sum += getRuntimeLength(field.get(o))
                }
            }
            return sum
        }
//        throw new IllegalArgumentException("Cannot determine length of type:" + clz.getName())
    }

    static byte[] getBytes(int n) {
        byte[] data = new byte[4]
        for (int i = 3; i >= 0; --i) {
            data[i] = (n & 0xff) as byte;
            n >>= 4
        }
        return data
    }

    static void writeNumber(Number value, int bytesLength, OutputStream outputStream) {
        long copy = value.longValue()
        def numBuf = NUM_BUF.get()
        int i = 0
        while (bytesLength > 0) {
            if (i == numBuf.length) {
                throw new IllegalArgumentException("Number bytes overflow")
            }
            numBuf[i++] = (byte) (copy & 0xff)
            copy >>= 8
            --bytesLength
        }
        // write big-endian
        while (--i >= 0) {
            outputStream.write(numBuf[i])
        }
    }

    /**
     * write and return length
     * @param o
     * @param outputStream
     * @return
     */
    static int writeTo(@Nonnull Object o, OutputStream outputStream) {
        int sum = 0
        def clz = o.getClass()
        if (clz.isArray()) {
            int len = Array.getLength(o)
            for (int i = 0; i < len; ++i) {
                sum += writeTo(Array.get(o, i), outputStream)
            }
            return sum
        }

        def fields = clz.getDeclaredFields()

        int n = fields.length
        for (int i = 0; i < n; i++) {
            Field field = fields[i]
            if (!isUserDefinedInstanceField(field)) {
                continue
            }
//            println "Writing field:${field.name} of ${clz.name}"
            def type = field.type
            field.setAccessible(true)
            def val = field.get(o)

            // non null array need not generation detection,so just write it
            if (val != null && val.getClass().isArray()) {
                writeTo(val, outputStream)
                continue
            }

            def fieldLength = getFieldNumericLength(field, type)
            if (fieldLength == -2) {
                continue
            }
            // numeric type or array
            if (fieldLength != -1) {
                if (val == null || val == -1) {
                    // value of this field can be calculated
                    Calculated calculatedPrefixLengthAnnotation = field.getAnnotation(Calculated.class)
                    Timestamp timestampAnnotation = null;
                    Randomized randomizedAnnotation = null;
//                    println "Calculated of field:${field.name} of ${clz.name} is ${calculatedPrefixLengthAnnotation}"
//                    println "search annotation for ${field.name}"
                    if (calculatedPrefixLengthAnnotation != null) {
                        int fieldCount = calculatedPrefixLengthAnnotation.value()
                        if (fieldCount == -1) {
                            fieldCount = n - i - 1;
                        }
                        if (fieldCount <= 0) {
                            throw new IllegalArgumentException("Illegal field count:" + calculatedPrefixLengthAnnotation.value());
                        }
                        val = 0
                        for (int j = 0; j < fieldCount; j++) {
                            Field nextField = fields[i + 1 + j]
                            if (!isUserDefinedInstanceField(nextField)) {
                                continue
                            }
                            nextField.setAccessible(true)
                            def nextValue = nextField.get(o)
                            if (nextValue == null && nextField.type.isArray()) {
                                continue
                            }
                            val += getRuntimeLength(nextValue)
                        }
                    } else if ((timestampAnnotation = field.getAnnotation(Timestamp.class)) != null) {
                        switch (timestampAnnotation.type()) {
                            case 0: val = System.currentTimeSeconds(); break
                            case 1: val = System.currentTimeMillis(); break
                            default: throw new IllegalArgumentException("Unsupported timestamp generation for unknown type:" + timestampAnnotation.type())
                        }
//                        println "Generate timestamp:${val}"
                    } else if ((randomizedAnnotation = field.getAnnotation(Randomized.class)) != null) {
                        // can also be byte[]
                        def localRandom = ThreadLocalRandom.current()
                        if (type == byte[].class || type == Byte[].class) {
                            for (int j = 0; j < fieldLength; j++) {
                                outputStream.write(localRandom.nextLong(randomizedAnnotation.lower(), randomizedAnnotation.upper()) as int);
                            }
                            // avoid writing
                            val = null;
                        } else {
                            val = localRandom.nextLong(randomizedAnnotation.lower(), randomizedAnnotation.upper())
                        }
                    } else {
                        // non generation annotation specified, so val null should be considered value 0
                        if (val == null) {
                            val = 0
                        }
                    }
                }
                sum += fieldLength
                if (val != null) {
                    // array can have @Length
                    // write fieldLength bytes
//                    println "field:${field.name},type:${val.getClass()}"
                    writeNumber((Number) val, fieldLength, outputStream)
                }
            } else {
                // complex type
                sum += writeTo(val, outputStream)
            }
        }
        return sum
    }

    private static boolean isUserDefinedInstanceField(Field field) {
        return !field.isSynthetic() && !Modifier.isStatic(field.getModifiers())
    }

    /**
     *
     * @param field
     * @param type
     * @return -1 not numeric field, -2 should be ignored, other value are considered good
     */
    private static int getFieldNumericLength(Field field, Class<?> type) {
// Length indicate simple value types
        int fieldLength = -1;
        Length lengthAnnotation = field.getAnnotation(Length.class)
        if (lengthAnnotation != null && lengthAnnotation.value() != -1) {
            fieldLength = lengthAnnotation.value()
            // this field is ignored
            if (fieldLength == 0) {
                return -2;
            }
        } else if (type == long.class || type == Long.class) {
            fieldLength = 8
        } else if (type == int.class || type == Integer.class) {
            fieldLength = 4
        } else if (type == short.class || type == Short.class) {
            fieldLength = 2
        } else if (type == byte.class || type == Byte.class) {
            fieldLength = 1
        }
        return fieldLength
    }

    static Object readFrom(Class<?> clz, InputStream inputStream) {
        return readFrom(clz, new IntPack(value: -1), inputStream)
    }
    /**
     * read fields specified
     * @param clz
     * @param fields
     * @param start
     * @param count
     * @param size
     * @param inputStream
     * @return
     */
    static void readFieldsFrom(Object o, Class<?> clz, Field[] fields, int start, int count, IntPack size, InputStream inputStream) {
        for (int i = 0; i < count; i++) {
            def field = fields[start + i]
            if (!isUserDefinedInstanceField(field)) {
                continue
            }
//            println "Reading field:${field.name}"
            def type = field.type
            field.setAccessible(true)
            def fieldLength = getFieldNumericLength(field, type)
//            println "field length = ${fieldLength}"
            // should be ignored
            if (fieldLength == -2) {
                continue
            }
//            println "before reading field:${field.name},size = ${size.value}"
            // numeric, variable-size array types  will be handled
            if (fieldLength != -1) {
                // an array
                if (type.isArray()) {
                    IntPack arrSize = new IntPack(value: fieldLength)
                    field.set(o, readFrom(type, arrSize, inputStream))
                    if (arrSize.value != 0) {
                        throw new IllegalArgumentException("Array is not fully read, expect:" + fieldLength + ", actual:" + (fieldLength - arrSize.value))
                    }
                    if (size.value != -1) {
                        size.value -= fieldLength
                    }
                } else {
                    long curSize = readNumericAndSet(o, field, fieldLength, inputStream)
//                    println "field:${field.name},read = ${curSize}"
                    if (size.value != -1) {
                        size.value -= fieldLength
                    }
                    // value of this field can be calculated
                    Calculated calculatedPrefixLengthAnnotation = field.getAnnotation(Calculated.class)
                    if (calculatedPrefixLengthAnnotation != null) {
                        int fieldCount = calculatedPrefixLengthAnnotation.value()
                        if (fieldCount == -1) {
                            fieldCount = count - i - 1;
                        }
                        if (fieldCount <= 0) {
                            throw new IllegalArgumentException("Illegal field count:" + calculatedPrefixLengthAnnotation.value());
                        }
                        IntPack enclosingPack = new IntPack(value: curSize)
                        readFieldsFrom(o, clz, fields, i + 1 + start, fieldCount, enclosingPack, inputStream)
                        // skip already read
                        i += fieldCount
                        if (enclosingPack.value != 0) {
                            throw new IllegalArgumentException("Object not fully read,declaring bytes:" + curSize + ", actual:" + (curSize - enclosingPack.value))
                        }
                        if (size.value != -1) {
                            size.value -= curSize
                        }
                    }
                }
            } else {
                def typedAnnotation = field.getAnnotation(Typed)
                if (typedAnnotation != null) {
                    def method = clz.getDeclaredMethod(typedAnnotation.value())
                    method.setAccessible(true)
                    type = method.invoke(o)
                }
                // another object type
                field.set(o, readFrom(type, size, inputStream))
            }
//            println "after reading field:${field.name},size = ${size.value}, json = ${JSON.toJSONString(field.get(o))}"
        }
    }

    /**
     *
     * @param clz
     * @param size -1 no size indication
     * @param inputStream
     * @return
     */
    static Object readFrom(Class<?> clz, IntPack size, InputStream inputStream) {
        if (clz.isArray()) {
            def subType = clz.getComponentType()
            /**
             * handle byte[] specially
             */
            if (subType == byte.class) {
                byte[] arr = null
                if (size.value >= 0) {
                    arr = new byte[size.value]
                    int n = inputStream.read(arr)
                    if (n != size.value) {
                        throw new IllegalArgumentException("Cannot read to byte[] fully,expected:" + size.value + ",actually read:" + n)
                    }
                } else {
                    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(1024)
                    IOUtils.copy(inputStream, byteArrayOutputStream)
                    arr = byteArrayOutputStream.toByteArray()
                }
                size.value = 0
                return arr
            }
            List<Object> list = new ArrayList<>(1)
            while (size.value == -1 || size.value > 0) {
                list.add(readFrom(subType, size, inputStream))
            }
            return list.toArray(Array.newInstance(subType, 0))
        } else if (clz.isEnum()) {
            Field valueField = clz.getDeclaredField("value")
            if (valueField == null || valueField.isSynthetic() || Modifier.isStatic(valueField.getModifiers())) {
                throw new IllegalArgumentException("Cannot find 'value' field of enum type:" + clz.getName())
            }
            int len = getFieldNumericLength(valueField, valueField.type)
            if (len == -2) {
                return null
            }
            if (len == -1) {
                throw new IllegalArgumentException("Cannot determine a way to identify enumeration with a non-numeric type of field 'value'")
            }
            if (size.value != -1 && len > size.value) {
                throw new IllegalArgumentException("the field length exceeds predefined size")
            }
            def identityValue = readNumericFrom(valueField.type, len, inputStream) as int
            def obj = Utils.enumOfValue((Enum[]) clz.enumConstants, identityValue)
            if (obj == null) {
                throw new IllegalArgumentException("Cannot deserialize enum type:" + clz.getName() + ", identity value = " + identityValue)
            }
            if (size.value != -1) {
                size.value -= len
            }
            return obj
        } else if (clz == long.class || clz == Long.class) {
            def val = readNumericFrom(clz, size.value == -1 ? 8 : size.value, inputStream)
            if (size.value != -1) {
                size.value -= 8
            }
            return val
        } else if (clz == int.class || clz == Integer.class) {
            def val = readNumericFrom(clz, size.value == -1 ? 4 : size.value, inputStream)
            if (size.value != -1) {
                size.value -= 4
            }
            return val
        } else if (clz == short.class || clz == Short.class) {
            def val = readNumericFrom(clz, size.value == -1 ? 2 : size.value, inputStream)
            if (size.value != -1) {
                size.value -= 2
            }
            return val
        } else if (clz == byte.class || clz == Byte.class) {
            def val = readNumericFrom(clz, size.value == -1 ? 1 : size.value, inputStream)
            if (size.value != -1) {
                size.value -= 1
            }
            return val
        } else {
            def fields = clz.getDeclaredFields()
            def o = clz.newInstance()
            readFieldsFrom(o, clz, fields, 0, fields.length, size, inputStream)
            return o
        }
    }

    static long readNumericAndSet(Object o, Field field, int length, InputStream inputStream) {
        if (length > 8) {
            throw new IllegalArgumentException("Cannot deserialize a numeric chunk with size greater bytes than 8, given size = " + length)
        }
        long value = 0
        while (length-- > 0) {
            value = (value << 8) | inputStream.read()
        }
        def clz = field.type
        if (clz == long.class || clz == Long.class) {
            field.setLong(o, value)
        } else if (clz == int.class || clz == Integer.class) {
            field.setInt(o, (int) value)
        } else if (clz == short.class || clz == Short.class) {
            field.setShort(o, (short) value)
        } else if (clz == byte.class || clz == Byte.class) {
            field.setByte(o, (byte) value)
        } else {
            throw new IllegalArgumentException("Unable to convert deserialized numeric value to type:" + clz.getName())
        }
        return value
    }

    static Object readNumericFrom(Class<?> clz, int length, InputStream inputStream) {
        if (length > 8) {
            throw new IllegalArgumentException("Cannot deserialize a numeric chunk with size greater bytes than 8, given size = " + length)
        }
        long value = 0
        while (length-- > 0) {
            value = (value << 8) | inputStream.read()
        }
        if (clz == long.class || clz == Long.class) {
            return value
        } else if (clz == int.class || clz == Integer.class) {
            return (int) value
        } else if (clz == short.class || clz == Short.class) {
            return (short) value
        } else if (clz == byte.class || clz == Byte.class) {
            return (byte) value
        } else {
            throw new IllegalArgumentException("Unable to convert deserialized numeric value to type:" + clz.getName())
        }
    }

}
