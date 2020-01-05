package com.fulton_shaw.net.tls_https

import com.alibaba.fastjson.JSON
import com.alibaba.fastjson.serializer.SerializerFeature
import com.fulton_shaw.net.tls_https.annotations.Calculated
import com.fulton_shaw.net.tls_https.annotations.Length
import com.fulton_shaw.net.tls_https.annotations.Randomized
import com.fulton_shaw.net.tls_https.annotations.Timestamp
import com.fulton_shaw.net.tls_https.annotations.Typed
import com.fulton_shaw.net.tls_https.support.IntPack
import groovy.transform.CompileStatic
import org.apache.commons.io.HexDump
import org.apache.commons.io.IOUtils

import javax.annotation.Nonnull
import javax.annotation.Nullable
import java.lang.reflect.Array
import java.lang.reflect.Field
import java.lang.reflect.Modifier
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentMap
import java.util.concurrent.ThreadLocalRandom

import static com.fulton_shaw.net.tls_https.FieldUtils.getFields;


class LocalBuffers {

    private LocalBuffers() {}
    private static final ThreadLocal<byte[]> NUM_BUF8 = new ThreadLocal<byte[]>() {
        @Override
        protected byte[] initialValue() {
            return new byte[8]
        }
    }


    public static byte[] get8BytesInstance() {
        return NUM_BUF8.get()
    }

}

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


    static String fieldsToJson(Object o) {
        return fieldsToJson(o, 0)
    }

    static String fieldsToJson(Object o, int level) {
        if (o == null) {
            return "null"
        }
        def clz = o.getClass()
        if (clz == String.class || clz == Character.class || clz == char.class || clz == Long.class || clz == long.class || clz == Integer.class || clz == int.class || clz == Short.class || clz == short.class || clz == boolean.class || clz == Boolean.class || clz == Byte.class || clz == byte.class || Map.class.isAssignableFrom(clz) || List.class.isAssignableFrom(clz) || clz.isEnum()) {
            return JSON.toJSONString(o, SerializerFeature.PrettyFormat)
        }
        if (clz.isArray()) {
            def subType = clz.getComponentType()
            if (subType == byte.class || subType == Byte.class) {
                return '"hex:' + HexUtils.getHexString((byte[]) o) + ',ascii:' + toPrintableAscii((byte[]) o) + '"'
            }
            def length = Array.getLength(o)
            def s = new StringBuilder(length * 4)
            s.append('[')
            for (int i = 0; i < length; i++) {
                s.append(fieldsToJson(Array.get(o, i), level + 1)).append(",")
            }
            if (s.length() > 0) {
                s.deleteCharAt(s.length() - 1)
            }
            s.append(']')
            return s.toString()
        } else if (Collection.class.isAssignableFrom(clz)) {
            Collection c = (Collection) o
            def s = new StringBuilder(c.size() * 4)
            s.append('[')
            for (def e : c) {
                s.append(fieldsToJson(e, level + 1)).append(",")
            }
            if (s.length() > 0) {
                s.deleteCharAt(s.length() - 1)
            }
            s.append(']')
            return s.toString()
        }
        def fields = getFields(clz)
        def s = new StringBuilder(fields.length * 10)
//        for (int i = 0; i < level; ++i) {
//            s.append('     ')
//        }
        // MARK: debug
//        println "serializing : ${clz.getSimpleName()}"
        s.append("{/*${clz.getSimpleName()}*/\n")
        for (def field : fields) {
            for (int i = 0; i <= level; ++i) {
                s.append('     ')
            }
            s.append(JSON.toJSONString(field.name)).append(": ").append(
                    fieldsToJson(field.get(o), level + 1)).append("\n")
        }
        for (int i = 0; i < level; ++i) {
            s.append('     ')
        }
        s.append("}")
        return s.toString()
    }


    static char toPrintableAscii(byte b) {
        if (b >= (char) ' ' && b <= (char) '~') {
            return (char) b
        } else {
            return '.'
        }
    }

    static String toPrintableAscii(byte[] arr) {
        StringBuilder stringBuilder = new StringBuilder(arr.length)
        for (int i = 0; i < arr.length; i++) {
            stringBuilder.append(toPrintableAscii(arr[i]))
        }
        return stringBuilder.toString()
    }
}

class FieldUtils {
    private FieldUtils() {}

    private static final ConcurrentMap<Class<?>, Field[]> FIELDS_MAP = new ConcurrentHashMap<>()
    private static final Field[] EMPTY = new Field[0]

    public static Field[] getFields(@Nullable Class<?> clz) {
        if (clz == null || clz == Object.class) {
            return EMPTY
        }
        def fields = FIELDS_MAP.get(clz)
        if (fields == null) {
            fields = new ArrayList<Field>(10)
            // for enum, name, ordinal are auto generated,so do not include them
            if (!clz.isEnum()) {
                fields.addAll(getFields(clz.getSuperclass()))
            }
            def allFields = clz.getDeclaredFields()
            for (int i = 0; i < allFields.length; i++) {
                if (!isUserDefinedInstanceField(allFields[i])) {
                    continue
                }
                allFields[i].setAccessible(true)
                fields.add(allFields[i])
            }
            FIELDS_MAP.putIfAbsent(clz, fields.toArray(new Field[0]))
            fields = FIELDS_MAP.get(clz)
        }
        return fields
    }

    static boolean isUserDefinedInstanceField(Field field) {
        return !field.isSynthetic() && !Modifier.isStatic(field.getModifiers())
    }
}

class SerializeUtils {

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
            def fields = getFields(clz)
            int n = fields.length
            for (int i = 0; i < n; i++) {
                def field = fields[i]

                // the Length annotation can be used to statically define the length
                def lengthAnnotation = field.getAnnotation(Length.class)
                if (lengthAnnotation != null && lengthAnnotation.value() != -1) {
                    sum += lengthAnnotation.value()
                } else {
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
//        long copy = value.longValue()

        def bytes = HexUtils.splitLittleEndian(value.longValue())
        int n = 0
        while (bytes[n] != (byte) 0) {
            ++n
        }
        if (n > bytesLength) {
            throw new IllegalArgumentException("Number bytes overflow")
        }
        // write big-endian
        while (--n >= 0) {
            outputStream.write(bytes[n])
        }

//        def numBuf = LocalBuffers.get8BytesInstance()
//        int i = 0
//        while (bytesLength > 0) {
//            if (i == numBuf.length) {
//                throw new IllegalArgumentException("Number bytes overflow")
//            }
//            numBuf[i++] = (byte) (copy & 0xff)
//            copy >>= 8
//            --bytesLength
//        }
//        // write big-endian
//        while (--i >= 0) {
//            outputStream.write(numBuf[i])
//        }
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
            def subType = clz.getComponentType()

            int len = Array.getLength(o)
            def numericLength = getNumericTypeLength(subType)
            if (numericLength != -1) {
                for (int i = 0; i < len; ++i) {
                    writeNumber((Number) Array.get(o, i), numericLength, outputStream)
                    sum += numericLength
                }
            } else {
                for (int i = 0; i < len; ++i) {
                    sum += writeTo(Array.get(o, i), outputStream)
                }
            }
            return sum
        }

        def fields = getFields(clz)
        int n = fields.length
        for (int i = 0; i < n; i++) {
            Field field = fields[i]
//            println "Writing field:${field.name} of ${clz.name}"
            def type = field.type
            def val = field.get(o)

            // non null array need not generation detection,so just write it
//            println "Writing field of field:${field.name} of ${clz.name}"
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
        } else {
            fieldLength = getNumericTypeLength(type)
        }
        return fieldLength
    }

    private static int getNumericTypeLength(Class<?> type) {
        if (type == long.class || type == Long.class) {
            return 8
        } else if (type == int.class || type == Integer.class) {
            return 4
        } else if (type == short.class || type == Short.class) {
            return 2
        } else if (type == byte.class || type == Byte.class) {
            return 1
        }
        return -1
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
//            println "Reading field:${field.name}"
            def type = field.type
            def fieldLength = getFieldNumericLength(field, type)
//            println "field length = ${fieldLength}"
            // should be ignored
            if (fieldLength == -2) {
                continue
            }
//             MARK: debug
//            println "before reading field:${field.name} of ${clz.name},size = ${size.value}"
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
                        // MARK: debug
//                        println "field:${field.name},next size = ${curSize}"
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
            // MARK: debug
//            println "after reading ${field.name} of ${clz.name},size = ${size.value}, json = ${Utils.fieldsToJson(field.get(o))}"
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
            def fields = getFields(clz)
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

@CompileStatic
class EncodingUtils {
    private EncodingUtils() {}

    public static byte[] encode7BitGroupToByteArray(byte[] data) {
        return encode7BitGroupToByteArray(data, 0, data.length)
    }

    /**
     * the input is considered
     * leading zeros are ommited
     * @param data
     * @return
     */
    public static byte[] encode7BitGroupToByteArray(byte[] data, int offset, int len) {
        // detect the length by locating the most significant bit

        int bitLength = BitUtils.getSignificantBitLength(data)
        // groovy implements / using BigDecimal
        int total = bitLength.intdiv(7) + (bitLength % 7 > 0 ? 1 : 0)

        // MARK: debug
//        println "bitLength = ${bitLength}, total = ${total}"

        // we have a constraint,
        //  let n = data.length, s = result length
        //  set target[i] to destination, source[i] the original
        //  target[s-1] = source[n-1] & 0x7f
        //  target[i] = bit [7*(s - i - 1) ,7*(s - i) ),  (i<s-1)
        //   let h=n - 1 - 7*(s-i-1)/8, t=8 - 7*(s-i-1)%8
        //    if t==0, then it starts in the boundary, then target[i] = source[h] | 0x80
        //    if t==1, then it starts in the 1st bit, then target[i] = (source[h]>>1) | 0x80
        //    otherwise,target[i] = ((source[h]>>t) | (source[h-1]<<7-t)) | 0x80
        //  all bit operations are considered using int(java will convert byte to int),so negative bit will not affect the result
        // [i] (i>0) hiBit=1

        byte[] out = new byte[total]
        if (total > 0) {
            // last one
            out[total - 1] = (byte) (data[data.length - 1] & 0x7f)
//            println "last = ${Utils.getHexString(data[data.length - 1])} ,${data[data.length - 1] & 0x7f},${Utils.getHexString(out)}"
        }
        int idx = total - 2
        // loStart: the index which the first bit is in
        int loIndex = data.length - 1
        // loOffset: the offset in loIndex where the first bit is at
        // 8 - loOffset: usable bits in current index
        int loOffset = 7
        while (idx >= 0) {
//            println "idx=${idx}, loIdx = ${loIndex}, loOffset = ${loOffset}, data[${loIndex}]=${Utils.getHexString(data[loIndex])}"
            // invariant: 8 - loOffset >= 1
            if (loOffset <= 1) {
                out[idx] = (((data[loIndex] & 0xff) >> loOffset) | 0x80) as byte
            } else {
                out[idx] = ((((data[loIndex] & 0xff) >> loOffset) | ((data[loIndex - 1] << (8 - loOffset)))) | 0x80) as byte
//                println "out[${idx}] = ${Utils.getHexString(out[idx])}, lo = ${Utils.getHexString((data[loIndex] >>> loOffset) as byte)}, hi = ${Utils.getHexString(data[loIndex - 1] << (8 - loOffset) as byte)}"
            }

            // loOffset = 0, left 1 bit
            // loOffset = 1, left 0 bit
            // ...loOffset > 1, left no bit,
            //  must to next chunk
            if (--loOffset >= 0) {
                --loIndex
            } else {
                loOffset = 7
            }
            --idx
        }
        return out
    }

    public static int encode7BitGroup(byte[] data, int offset, int length, OutputStream outputStream) {
        def byteArray = encode7BitGroupToByteArray(data, offset, length)
        outputStream.write(byteArray)
        return length
    }
    /**
     *
     * @return bytes written
     */
    public static int encode7BitGroup(byte[] data, OutputStream outputStream) {
        return encode7BitGroup(data, 0, data.length, outputStream)
    }

    static byte[] decode7BitGroup(InputStream inputStream) {
        byte[] buf = new byte[8]
        int i = 0
        while (true) {
            int nextByte = inputStream.read()
            if (i == buf.length) {
                buf = Arrays.copyOf(buf, 2 * buf.length)
            }
            buf[i++] = (byte) nextByte
            // read until the highest bit is 0, that is the boundary
            if ((nextByte & 0x80) == 0) {
                break
            }
        }
        return decode7BitGroup(buf, 0, i)
    }

    static byte[] decode7BitGroup(byte[] buf) {
        return decode7BitGroup(buf, 0, buf.length)
    }

    static byte[] decode7BitGroup(byte[] buf, int offset, int length) {
        if (length == 0) {
            return new byte[0]
        }
        // determine size, find the first byte that is not 0x80
        int end = offset + length
        int nonEmptyIdx = offset
        while (nonEmptyIdx < end) {
            if (buf[nonEmptyIdx] != (byte) 0x80) {
                break
            }
            ++nonEmptyIdx
        }
        if (nonEmptyIdx == end) {
            throw new IllegalArgumentException("Illegal format of 7bit group, at least one byte should have its highest bit set to 0")
        }
//        println "nonEmptyIdx = ${nonEmptyIdx}"
        // count significant bits(exclude the highest bit)
        def leadingZeros = BitUtils.getLeadingZeroCount(buf[nonEmptyIdx], 0x40)
        int bitLength = (length - nonEmptyIdx) * 7 - leadingZeros

        int total = bitLength.intdiv(8) + (bitLength % 8 > 0 ? 1 : 0)

        // MARK: debug
//        println "length = ${length}, last = ${Utils.getHexString(buf[nonEmptyIdx])}, leadingZeros = ${leadingZeros}, bitLength = ${bitLength}, total = ${total}"

        byte[] data = new byte[total]

        int idx = total - 1
        int loIndex = end - 1
        // 7 - loOffset = usable bits, next chunk usable bits = 1 + loOffset, its left shift: 7 - loOffset
        // next loOffset = loOffset + 1
        int loOffset = 0
        while (idx >= 0) {
            // invariant: loOffset >=0 && loOffset < 7, the highest bit cannot be used
            // span exactly two chunk
            if (loIndex == 0) {
                data[idx] = ((buf[loIndex] & 0x7f) >> loOffset) as byte
            } else {
                data[idx] = (((buf[loIndex] & 0x7f) >> loOffset) | ((buf[loIndex - 1] << (7 - loOffset)))) as byte
            }
//            println "idx = ${idx}, loIdx=${loIndex}, hiByte = ${Utils.getHexString(buf[loIndex - 1])}, hiShift = ${7 - loOffset}, hi = ${Utils.getHexString(buf[loIndex - 1] << (7 - loOffset) as byte)}"
            // loOffset : 0->1->2
            if (++loOffset == 7) {
                // 1111_1111 1111_1111
                // skip one more chunk
                loOffset = 0
                --loIndex
            }
            --loIndex
            --idx
        }

        return data
    }

}

/**
 * java always apply signed extend:
 * the one's complement is extended with all 1 and remains the value being the same
 * for example:
 *    (byte)-155 = 0b10001101  (signed byte)
 *    -155 = 0b11111111111111111111111101100101 (signed integer extend)
 *  the one's complement makes signed extension easier
 *
 *  NOTE that extension always signed, not like operator >> and >>>
 *
 *  0x80 >> 7 = 0xff  !!!!
 *  0x80 >>> 7 = 0xff !!!!
 *  why?  0x80 -> int 0xffff_ff80
 *  to correctly get it, use (0x80 & 0xff) >> 7.  Only right shift needs to such care this
 */
class BitUtils {
    private BitUtils() {}

    static int getSignificantBitLength(byte[] data) {
        return getSignificantBitLength(data, 0, data.length)
    }
    /**
     * bits length, for example:  0b0111_0101 bit length = 7, the first non-zero appears at bit 7
     * @param data
     * @return
     */
    static int getSignificantBitLength(byte[] data, int offset, int len) {
        int nonzeroIdx = 0
        while (nonzeroIdx < len) {
            if (data[nonzeroIdx + offset] != (byte) 0) {
                break
            }
            ++nonzeroIdx
        }
        if (nonzeroIdx == len) {
            return 0
        }
        return (len - nonzeroIdx) * 8 - getLeadingZeroCount(data[nonzeroIdx + offset], 0x80)
    }

    /**
     * get leading zero, if highBitMask = 0x80, it counts all leading zeros
     * if highBitMask = 0x40, it counts all leading zeros from bit 6(inclusive)
     * etc.
     * @param b
     * @param highBitMask the highest bit to count
     * @return
     */
    static int getLeadingZeroCount(byte b, int highBitMask) {
        int count = 0
        while ((b & highBitMask) == 0) {
            ++count
            highBitMask >>>= 1
        }
        return count
    }

}

class HexUtils {
    private HexUtils() {}

    static String quoteToEscapeString(String hexString) {
        return quoteToEscapeString(parseHexString(hexString))
    }

    static String quoteToEscapeString(byte[] data) {
        StringBuilder stringBuilder = new StringBuilder(data.length * 4)
        for (int i = 0; i < data.length; i++) {
            stringBuilder.append("\\x").append(getHexChar((data[i] >> 4) & 0xf)).append(getHexChar(data[i] & 0xf))
        }
        return stringBuilder.toString()
    }

    static String getHexString(byte b) {
//        println "b=${b}, ${Integer.toBinaryString(b)},${Integer.toBinaryString(-155)}"
        // b扩展为整数，符号位
        return new StringBuilder(2).append(getHexChar((b >> 4) & 0xf)).append(getHexChar(b & 0xf)).toString()
    }

    static char getHexChar(int b) {
        return b >= 10 && b <= 16 ? ((char) 'a' + b - 10) : ((char) '0' + b)
    }

    static byte[] parseHexString(String s) {
//        010001fc0303de52501336e67ebd5b9924af1c65a2235bfae16d882286c7a07f7c29c73078ba20d8d8b910452fd670fc0315c39346c8cc1b4831df31fd402364cc9119413c172c00481302130313011304c02cc030cca9cca8c0adc02bc02fc0acc023c027c00ac014c009c013009dc09d009cc09c003d003c0035002f009fccaac09f009ec09e006b00670039003300ff0100016b00000012001000000d7777772e62616964752e636f6d000b000403000102000a000c000a001d0017001e00190018337400000010000e000c02683208687474702f312e31001600000017000000310000000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602002b0009080304030303020301002d00020101003300260024001d00202ac995cfd440523c314e81183ac4e113ae27d34ac5bd47bf9720fce470acd15e001500a600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
        if (s.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string length should be multiple of 2")
        }
        byte[] data = new byte[s.length() / 2]
        int j = 0
        for (int i = 0; i < data.length; ++i) {
            data[i] = parseHexChar(s.charAt(j), s.charAt(j + 1))
//            println "data[i]=${data[i]}"
            j += 2
        }
        return data
    }

    static String getHexString(byte[] arr) {
        return getHexString(arr, 0, arr.length)
    }

    static String getHexString(byte[] arr, int offset, int len) {
        StringBuilder stringBuilder = new StringBuilder(len * 2)
        for (int i = 0; i < len; i++) {
            stringBuilder.append(getHexChar((arr[i + offset] >> 4) & 0xf)).append(getHexChar(arr[i + offset] & 0xf))
        }
        return stringBuilder.toString()
    }

    static String getHexString(ByteArrayOutputStream outputStream) {
        return getHexString(outputStream.buf, 0, outputStream.count)
    }

    static byte parseHexChar(char sHi, char sLo) {
        return (((sHi >= (char) 'a' && sHi <= (char) 'f') ? (sHi - (char) 'a' + 10) : ((sHi >= (char) 'A' && sHi <= (char) 'F') ? sHi - (char) 'A' + 10 : sHi - (char) '0')) << 4) | ((sLo >= (char) 'a' && sLo <= (char) 'f') ? (sLo - (char) 'a' + 10) : ((sLo >= (char) 'A' && sLo <= (char) 'F') ? sLo - (char) 'A' + 10 : sLo - (char) '0'))
    }

    static String hexdump(byte[] data) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream(data.length * 4)
        HexDump.dump(data, 0, stream, 0)
        return stream.toString(StandardCharsets.UTF_8.name())
    }


    static long parseNumber(byte[] data) {
        return parseNumber(data, 0, data.length)
    }

    static long parseNumber(InputStream stream, int len) {
        long n = 0
        for (int i = 0; i < len; i++) {
            def data = stream.read()
            if (data == -1) {
                throw new IllegalArgumentException("Unexpected EOF of stream, expecting at least:" + (len - i) + " bytes")
            }
            n = (n << 8) | data
            if (n < 0) {
                throw new IllegalArgumentException("parse number from bytes overflow")
            }
        }
        return n
    }


    static long parseNumber(byte[] data, int offset, int length) {
        long n = 0
        for (int i = 0; i < length; i++) {
            // the & 0xff is important, because signed extension
            n = (n << 8) | (data[i + offset] & 0xff)
            if (n < 0) {
                throw new IllegalArgumentException("parse number from bytes overflow")
            }
        }
        return n
    }

    /**
     * return a byte array containing bytes from low to high, ending with 0
     * @param value
     * @return
     */
    static byte[] splitLittleEndian(long value) {
        def bytes = LocalBuffers.get8BytesInstance()

        int i = 0
        while (value != 0) {
            bytes[i++] = (value & 0xff) as byte
            value >>= 8
        }
        // set the last to zero,so the caller can identify the end
        while (i < bytes.length) {
            bytes[i++] = 0
        }
        return bytes
    }

    /**
     * start from end
     * @param value
     * @return
     */
    static byte[] splitBigEndian(long value) {
        def bytes = LocalBuffers.get8BytesInstance()

        int i = bytes.length
        while (value != 0) {
            bytes[--i] = (value & 0xff) as byte
            value >>= 8
        }
        // set the last to zero,so the caller can identify the end
        while (--i >= 0) {
            bytes[i] = 0
        }
        return bytes
    }

}

class DiffUtils {
    private DiffUtils() {}

    /**
     * return the first char, or -1 if they are the same
     * @param s1
     * @param s2
     * @return
     */
    static int diffChar(String s1, String s2) {

    }
}