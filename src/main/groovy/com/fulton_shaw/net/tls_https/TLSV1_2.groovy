package com.fulton_shaw.net.tls_https

import com.alibaba.fastjson.JSON
import com.fulton_shaw.net.tls_https.annotations.Calculated
import com.fulton_shaw.net.tls_https.annotations.Length
import com.fulton_shaw.net.tls_https.annotations.Randomized
import com.fulton_shaw.net.tls_https.annotations.Timestamp
import com.fulton_shaw.net.tls_https.annotations.Typed

import static com.fulton_shaw.net.tls_https.Utils.connect
import static com.fulton_shaw.net.tls_https.Utils.fromRawHexString
import static com.fulton_shaw.net.tls_https.Utils.hexdump


// duck type
enum ContentType {
    /**
     * 0x16 handshake
     */
    Handshake(22);
    byte value;

    ContentType(byte value) {
        this.value = value
    }

}

enum Version {
    V1_0(0x0301),
    V1_1(0x0302),
    V1_2(0x0303),
    V1_3(0x0304);
    short value;

    Version(int value) {
        this.value = (short) value
    }
}


enum CipherSuite {
    TLS_AES_256_GCM_SHA384(0x1302),
    TLS_CHACHA20_POLY1305_SHA256(0x1303),
    TLS_AES_128_GCM_SHA256(0x1301),
    TLS_AES_128_CCM_SHA256(0x1304),
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384(0xc02c),
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(0xc030),
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256(0xcca9),
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xcca8),
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM(0xc0ad),
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(0xc02b),
    // baidu used this
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(0xc02f),
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM(0xc0ac),
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256(0xc023),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256(0xc027),
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA(0xc00a),
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(0xc014),
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA(0xc009),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA(0xc013),
    TLS_RSA_WITH_AES_256_GCM_SHA384(0x009d),
    TLS_RSA_WITH_AES_256_CCM(0xc09d),
    TLS_RSA_WITH_AES_128_GCM_SHA256(0x009c),
    TLS_RSA_WITH_AES_128_CCM(0xc09c),
    TLS_RSA_WITH_AES_256_CBC_SHA256(0x003d),
    TLS_RSA_WITH_AES_128_CBC_SHA256(0x003c),
    TLS_RSA_WITH_AES_256_CBC_SHA(0x0035),
    TLS_RSA_WITH_AES_128_CBC_SHA(0x002f),
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384(0x009f),
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xccaa),
    TLS_DHE_RSA_WITH_AES_256_CCM(0xc09f),
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256(0x009e),
    TLS_DHE_RSA_WITH_AES_128_CCM(0xc09e),
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256(0x006b),
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256(0x0067),
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA(0x0039),
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA(0x0033),
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV(0x00ff);
    short value;

    CipherSuite(int value) {
        this.value = (short) value
    }
}

enum SignatureHashAlgorithmExtension {
    ecdsa_secp256r1_sha256(0x0403),
    ecdsa_secp384r1_sha384(0x0503),
    ecdsa_secp521r1_sha512(0x0603),
    ed25519(0x0807),
    ed448(0x0808),
    rsa_pss_pss_sha256(0x0809),
    rsa_pss_pss_sha384(0x080a),
    rsa_pss_pss_sha512(0x080b),
    rsa_pss_rsae_sha256(0x0804),
    rsa_pss_rsae_sha384(0x0805),
    rsa_pss_rsae_sha512(0x0806),
    rsa_pkcs1_sha256(0x0401),
    rsa_pkcs1_sha384(0x0501),
    rsa_pkcs1_sha512(0x0601),
    SHA224_ECDSA(0x0303),
    ecdsa_sha1(0x0203),
    SHA224_RSA(0x0301),
    rsa_pkcs1_sha1(0x0201),
    SHA224_DSA(0x0302),
    SHA1_DSA(0x0202),
    SHA256_DSA(0x0402),
    SHA384_DSA(0x0502),
    SHA512_DSA(0x0602);

    short value;

    SignatureHashAlgorithmExtension(int value) {
        this.value = (short) value
    }
}

enum CompressionMethod {
    NULL(0);

    byte value;

    CompressionMethod(int value) {
        this.value = (byte) value
    }
}

class TLSRecord<T> {
    ContentType contentType;
    Version version;
    @Calculated
    short length = -1;
    T data;
}
//==========
enum HandshakeType {
    ClientHello(1);
    byte value;

    HandshakeType(int value) {
        this.value = (byte) value
    }
}

class Random {
    @Timestamp
    int unixTime = -1;
    @Length(28)
    @Randomized
    byte[] randomBytes;
}

enum ExtensionType {
    server_name(0),
    ec_point_formats(11),

    supported_groups(0xa),

    next_protocol_negotiation(0x3374),

    application_layer_protocol_negotiation(0x10),

    encrypt_then_mac(0x16),

    extended_master_secret(0x17),

    post_handshake_auth(0x31),

    signature_algorithms(0x0d),

    supported_versions(0x2b),

    psk_key_exchange_modes(0x2d),

    key_share(0x33),

    padding(0x15);
    short value;

    ExtensionType(int value) {
        this.value = (short) value
    }


}

enum ServerNameType {
    host_name(0);
    byte value;

    ServerNameType(int value) {
        this.value = (byte) value
    }
}

enum PskKeyExchangeMode {
    PSK_WITH_EC_DHE(1);
    byte value;

    PskKeyExchangeMode(int value) {
        this.value = (byte) value
    }
}


class ServerNameExtension {
    @Calculated(Calculated.REMAINING)
    short length = -1;
    ServerNameType serverNameType;
    @Calculated
    short serverNameLength = -1;
    byte[] serverName;
}

class SignatureAlgorithmsExtension {
    @Calculated
    short length = -1
    SignatureHashAlgorithmExtension[] algorithms;
}

class SupportedVersionsExtension {
    @Calculated
    byte length = -1
    Version[] supportedVersions;
}

class PskExchangeModesExtension {
    @Calculated
    byte length = -1
    PskKeyExchangeMode pskKeyExchangeMode
}

class Extension<T> {
    ExtensionType extensionType;
    @Calculated
    short length = -1;
    @Typed("determineExtensionDataType")
    T extensionData;

    Class<?> determineExtensionDataType() {
        switch (extensionType) {
            case ExtensionType.server_name:
                return ServerNameExtension.class
            case ExtensionType.signature_algorithms:
                return SignatureAlgorithmsExtension.class;
            case ExtensionType.supported_versions:
                return SupportedVersionsExtension.class
            default:
                return byte[].class
        }
    }
}

class ClientHello {
    HandshakeType handshakeType;
    @Length(3)
    @Calculated(-1)
    int length = -1;// actual 3 bytes
    Version version;
    Random random = new Random();
    @Calculated
    byte sessionIdLength = -1;
    byte[] sessionId;
    // length in bytes, each cipher is two bytes
    @Calculated
    short cipherSuiteLength = -1;
    CipherSuite[] cipherSuites;
    @Calculated
    byte compressionMethodLength = -1;
    CompressionMethod[] compressionMethods;
    @Calculated
    short extensionLength = -1;
    Extension<?>[] extensions;
}


def run1() {
    def socket = connect("www.baidu.com", 443)


    data = ''


    socket.getOutputStream().write('')
}

def run_structToBytes() {
    ClientHello clientHello = new ClientHello()
    // is
    println clientHello.getProperties()
    Map map = ["A": "B"]
    println map.getProperties()
}

def run_serialize() {
    ClientHello clientHello = new ClientHello()

    clientHello.handshakeType = HandshakeType.ClientHello
    clientHello.version = Version.V1_2
    clientHello.sessionId = "\u0001\u0002".getBytes()

    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()
    SerializeUtils.writeTo(clientHello, byteArrayOutputStream)

    def array = byteArrayOutputStream.toByteArray()

    print hexdump(array)
    print JSON.toJSONString(clientHello, true)

    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(array)

    def clientHelloFromStream = SerializeUtils.readFrom(ClientHello.class, byteArrayInputStream)

    print JSON.toJSONString(clientHelloFromStream, true)
}

def run_fromHex() {
    def sHi = (char) '1'
    def sLo = (char) '1'
    println(((sHi >= (char) 'a' && sHi <= (char) 'f') ? (sHi - (char) 'a' + 10) : ((sHi >= (char) 'A' && sHi <= (char) 'F') ? sHi - (char) 'A' + 10 : sHi - (char) '0')) << 4)
    println((sLo >= (char) 'a' && sLo <= (char) 'f') ? (sLo - (char) 'a' + 10) : ((sLo >= (char) 'A' && sLo <= (char) 'F') ? sLo - (char) 'A' + 10 : sLo - (char) '0'))
    String s = '010001fc0303de52501336e67ebd5b9924af1c65a2235bfae16d882286c7a07f7c29c73078ba20d8d8b910452fd670fc0315c39346c8cc1b4831df31fd402364cc9119413c172c00481302130313011304c02cc030cca9cca8c0adc02bc02fc0acc023c027c00ac014c009c013009dc09d009cc09c003d003c0035002f009fccaac09f009ec09e006b00670039003300ff0100016b00000012001000000d7777772e62616964752e636f6d000b000403000102000a000c000a001d0017001e00190018337400000010000e000c02683208687474702f312e31001600000017000000310000000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602002b0009080304030303020301002d00020101003300260024001d00202ac995cfd440523c314e81183ac4e113ae27d34ac5bd47bf9720fce470acd15e001500a600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    def arr = fromRawHexString(s)

    println hexdump(arr)
}

def run_parseClientHelloFromRaw() {
    String s = '010001fc0303de52501336e67ebd5b9924af1c65a2235bfae16d882286c7a07f7c29c73078ba20d8d8b910452fd670fc0315c39346c8cc1b4831df31fd402364cc9119413c172c00481302130313011304c02cc030cca9cca8c0adc02bc02fc0acc023c027c00ac014c009c013009dc09d009cc09c003d003c0035002f009fccaac09f009ec09e006b00670039003300ff0100016b00000012001000000d7777772e62616964752e636f6d000b000403000102000a000c000a001d0017001e00190018337400000010000e000c02683208687474702f312e31001600000017000000310000000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602002b0009080304030303020301002d00020101003300260024001d00202ac995cfd440523c314e81183ac4e113ae27d34ac5bd47bf9720fce470acd15e001500a600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'

    def arr = fromRawHexString(s)


    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(arr)

    ClientHello clientHelloFromStream = SerializeUtils.readFrom(ClientHello.class, byteArrayInputStream)


    println JSON.toJSONString(clientHelloFromStream, true)

    println new String((clientHelloFromStream.extensions[0].extensionData as ServerNameExtension).serverName)

    ByteArrayOutputStream bo = new ByteArrayOutputStream()
    SerializeUtils.writeTo(clientHelloFromStream, bo)
    def byteArray = bo.toByteArray()
    def s2 = Utils.toRawHexString(byteArray)
    println s2
    // this indicates good
    assert s2 == s

}

//run_fromHex()
//run_serialize()
run_parseClientHelloFromRaw()