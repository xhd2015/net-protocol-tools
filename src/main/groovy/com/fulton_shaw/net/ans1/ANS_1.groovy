package com.fulton_shaw.net.ans1

import com.fulton_shaw.net.tls_https.EncodingUtils
import com.fulton_shaw.net.tls_https.HexUtils
import com.fulton_shaw.net.tls_https.Utils
import com.fulton_shaw.net.tls_https.annotations.Calculated
import com.fulton_shaw.net.tls_https.support.IntPack
import groovy.transform.CompileStatic
import org.apache.commons.codec.binary.Hex

import static com.fulton_shaw.net.tls_https.HexUtils.parseHexString

enum DataClass {
    UNIVERSAL(0b00),
    APPLICATION(0b01),
    CONTEXT_SPECIFIC(0b10),
    PRIVATE(0b11)

    byte value;

    DataClass(int value) {
        this.value = (byte) value
    }
}

enum Tag {
    NULL(0x05),
    OBJECT_IDENTIFIER(0x06),
    PrintableString(0x13),
    UTC_TIME(0x17);
    byte value;

    Tag(int value) {
        this.value = (byte) value
    }
}

class ANS_1Data<T> {
    DataClass dataClass;
    boolean structure;
    /**
     *  tag can be single byte or multiple bytes
     */
    byte[] tag;
    /**
     * length, will be transfered based on its length
     */
    @Calculated
    int length = -1;
    /**
     * based the dataClass and the tag
     * for structure, it is ANS_1Data[]
     * for non structure, it maybe byte[], or ObjectIdentifier, anything is possible
     */
    T content;
//    byte[] content;
}

class ObjectIdentifier {
    /**
     * a list of ids
     */
    long[] ids;
}

class UTCTime {
    /**
     * example:19-05-09 01:22:02Z
     * char= 1 9 0 5 0 5 0 9 0 1 2 2 0 2 Z
     */
    char[] utcString;
}

@CompileStatic
class ANS_1Decoder {
    ANS_1Data decode(InputStream stream) {
        return decode(stream, new IntPack(value: -1))
    }
    /**
     * decode a data, if reached end of stream, returns null
     * @param stream
     * @return
     */
    ANS_1Data decode(InputStream stream, IntPack size) {
        if (size.value == 0) {
            return null
        }
        int b = stream.read()
        if (b == -1) {
            if (size.value == -1) {
                return null
            }
            throw new IllegalArgumentException("Stream not fully read, expecting:" + size.value)
        }
        --size.value
        ANS_1Data data = new ANS_1Data()
        // bit[7,6] denotes the data class
        data.dataClass = Utils.enumOfValue(DataClass.values(), (b & 0xff) >> 6)
        // bit[5] denotes method
        data.structure = ((b & 0x20) != 0)
        // bit[4,0] denotes tag, if it is 0x3f, then multiple bytes tag
        int tag = b & 0x1f
        if (tag != 0x1f) {
            data.tag = new byte[1];
            data.tag[0] = (byte) tag
        } else {
            data.tag = EncodingUtils.decode7BitGroup(stream)
            size.value -= data.tag.length
        }
        int lengthByte = stream.read()
        --size.value
        // length, if bit[7] = 0, then single byte length, otherwise multiple bytes length
        if ((lengthByte & 0x80) == 0) {
            data.length = lengthByte
        } else {
            int followingLength = (lengthByte & 0x7f)
            data.length = (int) HexUtils.parseNumber(stream, followingLength)
            size.value -= followingLength
        }
        // if this is a structure, we can parse data as an array
        if (data.structure) {
            List<ANS_1Data> dataList = new ArrayList<>(1)
            IntPack leftSize = new IntPack(value: data.length)
            while (leftSize.value > 0) {
                def decoded = decode(stream, leftSize)
                if (decoded == null) {
                    throw new IllegalArgumentException("Decode error, cannot decode a structure data")
                }
                dataList.add(decoded)
            }
            size.value -= data.length
            data.content = dataList.toArray(new ANS_1Data<?>[0])
        } else {
            boolean handledAsNonByteArray = false;
            if (data.dataClass == DataClass.UNIVERSAL) {
                if (data.tag.length == 1 && data.tag[0] == Tag.OBJECT_IDENTIFIER.value/*tag*/) {
                    List<Long> ids = new ArrayList<>(3)
                    long leftSize = data.length
                    if (leftSize == 0) {
                        throw new IllegalArgumentException("Object Identifier expecting at least one byte")
                    }
                    def head = stream.read()
                    ids.add(head.intdiv(40) as long)
                    ids.add((head % 40) as long)
                    --leftSize
                    while (leftSize > 0) {
                        def group = EncodingUtils.decode7BitGroup(stream)
                        // MARK: debug
//                        println "group = ${HexUtils.getHexString(group)}"
                        ids.add(HexUtils.parseNumber(group))
                        leftSize -= group.length
                    }
                    data.content = new ObjectIdentifier(ids: ids.stream().mapToLong({ Long i -> i.longValue() }).toArray())
                    handledAsNonByteArray = true
                } else if (data.tag.length == 1 && data.tag[0] == Tag.UTC_TIME.value) {
                    char[] utcString = new char[data.length]
                    for (int i = 0; i < utcString.length; i++) {
                        utcString[i] = stream.read()
                    }
                    data.content = new UTCTime(utcString: utcString)
                    handledAsNonByteArray = true
                }
            }
            if (!handledAsNonByteArray) {
                def content = new byte[data.length]
                def read = stream.read(content)
                if (read != content.length) {
                    throw new IllegalArgumentException("Content not fully read,declared:" + content.length + ", actual:" + read)
                }
                data.content = content
            }
            size.value -= data.length
        }
        return data
    }


}

@CompileStatic
class ANS_1Encoder {
    /**
     * for some reason, we should encode the content first, so that we known the length
     * @param data
     * @param outputStream
     * @return
     */
    private int encodeContent(ANS_1Data data, OutputStream outputStream) {
        if (data.content == null) {
            return 0
        }
        int contentTotal = 0
        if (data.structure) {
            def content = data.content
            if (!(content.getClass().isArray()) || !ANS_1Data.class.isAssignableFrom(content.getClass().getComponentType())) {
                throw new IllegalArgumentException("content of structured data should be an array of ANS_1Data also")
            }
            ANS_1Data<?>[] arr = content as ANS_1Data<?>[]
            for (ANS_1Data arrData : arr) {
                contentTotal += encode(arrData, outputStream)
            }
        } else if (data.content instanceof ObjectIdentifier) {
            ObjectIdentifier identifier = data.content as ObjectIdentifier
            if (identifier.ids == null || identifier.ids.length < 2) {
                throw new IllegalArgumentException("OBJECT IDENTIFIER should contains at least 2 number")
            }
            assert (identifier.ids[0] >= 0 && identifier.ids[0] <= 2): "first number of identifier should reside in [0,2],actual " + identifier.ids[0]
            assert (identifier.ids[1] >= 0 && identifier.ids[0] < 40): "second number of identifier should reside in [0,40),actual " + identifier.ids[1]
            byte firstByte = ((40 * identifier.ids[0]) + identifier.ids[1]) as byte
            ++contentTotal
            outputStream.write(firstByte)
            for (int i = 2; i < identifier.ids.length; i++) {
                if (identifier.ids[i] <= 0x7f) {
                    outputStream.write(identifier.ids[i] as int)
                    ++contentTotal
                } else {
                    def endianBytes = HexUtils.splitBigEndian(identifier.ids[i])
                    int k = 0
                    while (endianBytes[k] == (byte) 0) {
                        ++k
                    }
//                    println "id=${identifier.ids[i]},bytes=${HexUtils.getHexString(endianBytes)},k=${k}"
                    contentTotal += EncodingUtils.encode7BitGroup(endianBytes, k, endianBytes.length - k, outputStream)
                }
            }
        } else if (data.content instanceof UTCTime) {
            UTCTime utcTime = data.content as UTCTime
            for (int i = 0; i < utcTime.utcString.length; i++) {
                outputStream.write(utcTime.utcString[i] as int)
            }
            contentTotal += utcTime.utcString.length
        } else if (data.content instanceof byte[]) {
            byte[] byteContent = data.content as byte[]
            outputStream.write(byteContent)
            contentTotal += byteContent.length
        } else {
            throw new IllegalArgumentException("Unknown content type:" + data.content.getClass().getName())
        }
        return contentTotal
    }
    /**
     * encode data to stream, and return bytes totally write
     * @param data
     * @param outputStream
     * @return
     */
    int encode(ANS_1Data data, OutputStream outputStream) {
        // we need to calculate content to decide the length
        ByteArrayOutputStream predecodedContent = null
        if (data.length == -1) {
            predecodedContent = new ByteArrayOutputStream(128)
            data.length = encodeContent(data, predecodedContent)
        }
        // automatically assign tags
        if (data.tag == null) {
            if (data.content instanceof ObjectIdentifier) {
                data.tag = new byte[1]
                data.tag[0] = Tag.OBJECT_IDENTIFIER.value
            } else if (data.content instanceof UTCTime) {
                data.tag = new byte[1]
                data.tag[0] = Tag.UTC_TIME.value
            } else {
                throw new IllegalArgumentException("Cannot detect tag for data")
            }
        }
        // MARK: debug
//        println "writing length:${data.length},content = ${Utils.fieldsToJson(data.content)}"
//        println "writing length:${data.length}"
        int sum = 1
        int first = ((data.dataClass.value << 6) | ((data.structure ? 1 : 0) << 5))
        if (data.tag.length == 1) {
            first |= (data.tag[0] & 0x1f)
            outputStream.write(first)
        } else {
            first |= 0x1f
            outputStream.write(first)
            sum += EncodingUtils.encode7BitGroup(data.tag, outputStream)
        }
        // MARK: debug
        if (data.length <= 0x7f) {
            outputStream.write(data.length)
            ++sum
        } else {
            def lengthBytes = HexUtils.splitLittleEndian(data.length)
            int n = 0
            while (lengthBytes[n] != (byte) 0) {
                ++n
            }
            // set highest bit = 1
            outputStream.write(n | 0x80)
            sum += n + 1
            while (--n >= 0) {
                outputStream.write(lengthBytes[n])
            }
        }

        sum += data.length
        if (predecodedContent != null) {
            predecodedContent.writeTo(outputStream)
        } else {
            int len = encodeContent(data, outputStream)
            if (len != data.length) {
                throw new IllegalArgumentException("ANS_1Data declares length " + data.length + ", actual " + len)
            }
        }

        return sum
    }
}

def verify7BitGroupEncodeAndDecode(byte[] data, String encoded) {

    def hex = HexUtils.getHexString(data)

    def actualEncoded = EncodingUtils.encode7BitGroupToByteArray(data)

    def encodedHex = HexUtils.getHexString(actualEncoded)
    assert encodedHex == encoded

    def decoded = EncodingUtils.decode7BitGroup(actualEncoded)

    def decodedHex = HexUtils.getHexString(decoded)
    assert decodedHex == hex
}

def run_encode7bitGroup() {
    // greater than 128
    verify7BitGroupEncodeAndDecode(parseHexString('01bb8d'), '86f70d')
    verify7BitGroupEncodeAndDecode(parseHexString('0137'), '8237')
    verify7BitGroupEncodeAndDecode(parseHexString('80'), '8100')
    // less than 128
    verify7BitGroupEncodeAndDecode(parseHexString('03'), '03')
    verify7BitGroupEncodeAndDecode(parseHexString('7f'), '7f')
}

def run_decodeData() {
    String s = '3009060355040613024245'
    def arr = parseHexString(s)
    ANS_1Decoder decoder = new ANS_1Decoder()

    def data = decoder.decode(new ByteArrayInputStream(arr))

    println Utils.fieldsToJson(data)

//    byte[] oid = data.content
//
//    def oidData = decoder.decode(new ByteArrayInputStream(oid))
//
//    println Utils.fieldsToJson(oidData)
}

def run_decodeIssuerOfCertificate() {

//    String s = '3066310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361313c303a06035504031333476c6f62616c5369676e204f7267616e697a6174696f6e2056616c69646174696f6e204341202d20534841323536202d204732'
    String s = '308209af30820897a003020102020c2cee193c188278ea3e437573300d06092a864886f70d01010b05003066310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361313c303a06035504031333476c6f62616c5369676e204f7267616e697a6174696f6e2056616c69646174696f6e204341202d20534841323536202d204732301e170d3139303530393031323230325a170d3230303632353035333130325a3081a7310b300906035504061302434e3110300e060355040813076265696a696e673110300e060355040713076265696a696e6731253023060355040b131c73657276696365206f7065726174696f6e206465706172746d656e7431393037060355040a13304265696a696e67204261696475204e6574636f6d20536369656e636520546563686e6f6c6f677920436f2e2c204c7464311230100603550403130962616964752e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100b4c6bfda53200fea40f3b85217663b36018d12b4990dd39b6c1853b11908b0fa73473e0d3a796278612e543c497c56dac0be6155d542706a10bef5bd8d6496210093630987b719ba0e203e49c853ed028f4601eba1079373bbedf1b3c9e2fbddf0392a83adf44198bc86eaba74a8a6e3d0e5c58eb30bb2d2ac91740eff80102336626508b487f5570c25c700d8f5a85db83341a72a5fdbfa709e21bbae4216660769fe1c262a810fab73e3d65220a46da86cd46648a46ff2680ac565a14ebf047a40431cd375fb75ac19d64a35056ecfd565d144ca6b0c5804c4854f1fbe2c32d1f1c628fbf92636b56dfacb96a2a0d0bcf851df0744bd8f6f67c0d4afd9cdc30203010001a382061930820615300e0603551d0f0101ff0404030205a03081a006082b06010505070101048193308190304d06082b060105050730028641687474703a2f2f7365637572652e676c6f62616c7369676e2e636f6d2f6361636572742f67736f7267616e697a6174696f6e76616c73686132673272312e637274303f06082b060105050730018633687474703a2f2f6f637370322e676c6f62616c7369676e2e636f6d2f67736f7267616e697a6174696f6e76616c73686132673230560603551d20044f304d304106092b06010401a03201143034303206082b06010505070201162668747470733a2f2f7777772e676c6f62616c7369676e2e636f6d2f7265706f7369746f72792f3008060667810c01020230090603551d130402300030490603551d1f04423040303ea03ca03a8638687474703a2f2f63726c2e676c6f62616c7369676e2e636f6d2f67732f67736f7267616e697a6174696f6e76616c7368613267322e63726c308203490603551d11048203403082033c820962616964752e636f6d8212636c69636b2e686d2e62616964752e636f6d8210636d2e706f732e62616964752e636f6d82106c6f672e686d2e62616964752e636f6d82147570646174652e70616e2e62616964752e636f6d8210776e2e706f732e62616964752e636f6d82082a2e39312e636f6d820b2a2e6169706167652e636e820c2a2e6169706167652e636f6d820d2a2e61706f6c6c6f2e6175746f820b2a2e62616964752e636f6d820e2a2e62616964756263652e636f6d82122a2e6261696475636f6e74656e742e636f6d820e2a2e62616964757063732e636f6d82112a2e62616964757374617469632e636f6d820c2a2e6261696661652e636f6d820e2a2e626169667562616f2e636f6d820f2a2e6263652e62616964752e636f6d820d2a2e626365686f73742e636f6d820b2a2e6264696d672e636f6d820e2a2e62647374617469632e636f6d820d2a2e6264746a7263762e636f6d82112a2e626a2e62616964756263652e636f6d820d2a2e636875616e6b652e636f6d820b2a2e646c6e656c2e636f6d820b2a2e646c6e656c2e6f726782122a2e647565726f732e62616964752e636f6d82102a2e6579756e2e62616964752e636f6d82112a2e66616e79692e62616964752e636f6d82112a2e677a2e62616964756263652e636f6d82122a2e68616f3132332e62616964752e636f6d820c2a2e68616f3132332e636f6d820c2a2e68616f3232322e636f6d820e2a2e696d2e62616964752e636f6d820f2a2e6d61702e62616964752e636f6d820f2a2e6d62642e62616964752e636f6d820c2a2e6d697063646e2e636f6d82102a2e6e6577732e62616964752e636f6d820b2a2e6e756f6d692e636f6d82102a2e736166652e62616964752e636f6d820e2a2e736d617274617070732e636e82112a2e73736c322e6475617070732e636f6d820e2a2e73752e62616964752e636f6d820d2a2e7472757374676f2e636f6d82122a2e7875657368752e62616964752e636f6d820b61706f6c6c6f2e6175746f820a6261696661652e636f6d820c626169667562616f2e636f6d820664777a2e636e820f6d63742e792e6e756f6d692e636f6d820c7777772e62616964752e636e82107777772e62616964752e636f6d2e636e301d0603551d250416301406082b0601050507030106082b06010505070302301d0603551d0e0416041476b5e6d649f8f836ea75a96d5e4d555b375cfdc7301f0603551d2304183016801496de61f1bd1c1629531cc0cc7d3b830040e61a7c30820104060a2b06010401d6790204020481f50481f200f0007600bbd9dfbc1f8a71b593942397aa927b473857950aab52e81a909664368e1ed1850000016a9a2ee19a000004030047304502202c7b4dc0f985478a2d0ac0793bd6b4b566f8aafb8258ad2336fe16bca6839921022100c02fcd9c9920cb7d915fd28bc6131073b5c1540333419fa66ac51493cf692b6b0076006f5376ac31f03119d89900a45115ff77151c11d902c10029068db2089a37d9130000016a9a2ede4f000004030047304502200332689e39d0eb5f1961dba712696f28448102a53cc2a313d57e98265f201aa0022100a78b62b3b0b44432e211ff458d55112c36ab299344c8345cce7c355731aeab12300d06092a864886f70d01010b05000382010100aab9cd528edc365d47d48bf3321706468360a327054929b11b466e38fe93fe09436cd2a158241242b7ab41f8470a7d64b575dc5a4514b2a4186b9cb73b8fb37ed2bdc0724b3505ae0d2d191f5073725adf97183bdb2af3de44ce642dc11e84cc76243e30672326e84ff70bf6ec69d77f51a9a06fb8c414e2c04a4ac4005d576ac941c4252b3218aa62a81e4981731c815f5efae49432c3506d8eaacc6c4c530cfa8f4e34799fa560c0f85075b8a19d01e6ab25230c3b2402405824ff34028b946110682fb680e3d05f4a0aa702d2c0983e1de802c8277126b2a887b6db9d10474bc2136234c6d03c390939258ffea2f4f3fbdf9b273dfcd028e86ddcdd17d31f'

    def arr = parseHexString(s)
    ANS_1Decoder decoder = new ANS_1Decoder()

    def data = decoder.decode(new ByteArrayInputStream(arr))

    println Utils.fieldsToJson(data)

    ANS_1Encoder encoder = new ANS_1Encoder()

    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(1024)
    def length = encoder.encode(data, byteArrayOutputStream)


    def encodedS = HexUtils.getHexString(byteArrayOutputStream)
//    println s
//    println encodedS
    assert encodedS == s

}

//run_encode7bitGroup()
//run_decodeData()
run_decodeIssuerOfCertificate()