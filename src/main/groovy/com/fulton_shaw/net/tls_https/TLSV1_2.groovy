package com.fulton_shaw.net.tls_https

import com.alibaba.fastjson.JSON
import com.fulton_shaw.net.tls_https.annotations.*

import static com.fulton_shaw.net.tls_https.Utils.*

// duck type
enum ContentType {
    /**
     * 0x16 handshake
     */
    Handshake(22),
    ChangeCipherSpec(20),
    ApplicationData(23)
    ;
    byte value;

    ContentType(int value) {
        this.value = (byte) value
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
//==========
enum HandshakeType {
    ClientHello(1),
    ServerHello(2),
    Certificate(11),
    ServerKeyExchange(12),
    ServerHelloDone(14),
    ClientKeyExchange(16);
    byte value;

    HandshakeType(int value) {
        this.value = (byte) value
    }
}

class TLSRecordEncrypted {
    ContentType contentType;
    Version version;
    @Calculated(Calculated.REMAINING)
    short length = -1;
    /**
     * this is encrypted
     */
    byte[] data;
}

class TLSRecord<T> {
    ContentType contentType;
    Version version;
    @Calculated(Calculated.REMAINING)
    short length = -1;
    @Typed("determineDataType")
    T data;

    Class<?> determineDataType() {
        switch (contentType) {
            case ContentType.Handshake:
                return HandshakeMessage.class
            case ContentType.ChangeCipherSpec:
                return ChangeCipherSpec.class
            case ContentType.ApplicationData:
                return ApplicationData.class
            default:
                return byte[].class
        }
    }

}

class HandshakeMessage<T> {
    HandshakeType handshakeType;
    @Length(3)
    @Calculated(Calculated.REMAINING)
    int protocolLength = -1;// actual 3 bytes
    @Typed("determineDataType")
    T data;

    Class<?> determineDataType() {
        switch (handshakeType) {
            case HandshakeType.ClientHello:
                return ClientHello.class
            case HandshakeType.ServerHello:
                return ServerHello.class
            case HandshakeType.Certificate:
                return Certificates.class
            case HandshakeType.ServerKeyExchange:
                return ServerKeyExchange.class
            case HandshakeType.ServerHelloDone:
                return ServerHelloDone.class
            default:
                return byte[].class
        }
    }
}

class ChangeCipherSpec {
    byte[] message;
}

class ApplicationData {
    byte[] data
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

    padding(0x15),
    renegotiation_info(0xff01)
    ;
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

class ALPNProtocol {
    @Calculated
    byte length = -1;
    byte[] protocolText;
}

class ApplicationLayerProtocolNegotiationExtension {
    @Calculated(Calculated.REMAINING)
    short length = -1
    ALPNProtocol[] protocols;
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
            case ExtensionType.application_layer_protocol_negotiation:
                return ApplicationLayerProtocolNegotiationExtension.class
            default:
                return byte[].class
        }
    }
}

class ClientHello {
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

class ServerHello {
    Version version;
    Random random = new Random();
    @Calculated
    byte sessionIdLength = -1;
    byte[] sessionId;
    CipherSuite cipherSuite;
    CompressionMethod compressionMethod;
    @Calculated
    short extensionLength = -1;
    Extension<?>[] extensions;
}

class Certificate {
    @Calculated
    @Length(3)
    int length;
    byte[] certificate;
}

class Certificates {
    @Calculated(Calculated.REMAINING)
    @Length(3)
    int allLengths;
    /**
     * a chain of certificate,
     * the first is server's certificate
     * and each of the following must certify the preceding one
     */
    Certificate[] certificateChain;
}

enum CurveType {
    named_curve(3);
    byte value;

    CurveType(int value) {
        this.value = (byte) value;
    }
}
/**
 * the EC Diffie-Hellman Server Params
 */
class ServerKeyExchange {
    CurveType curveType;
    /**
     * 0x17 = secp256r1
     */
    @Length(2)
    byte[] namedCurve;
    @Calculated
    byte pubkeyLength;
    byte[] pubkey;
    SignatureHashAlgorithmExtension signatureAlgorithm;
    @Calculated
    short signatureLength;
    byte[] signature;
}

class ServerHelloDone {

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

    print HexUtils.hexdump(array)
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
    def arr = HexUtils.parseHexString(s)

    println HexUtils.hexdump(arr)
}

def run_parseClientHelloFromRaw() {
//    println Number.class.isAssignableFrom(long.class)
//    println FieldUtils.getFields(ContentType.class)
    String s = '1603010200010001fc0303de52501336e67ebd5b9924af1c65a2235bfae16d882286c7a07f7c29c73078ba20d8d8b910452fd670fc0315c39346c8cc1b4831df31fd402364cc9119413c172c00481302130313011304c02cc030cca9cca8c0adc02bc02fc0acc023c027c00ac014c009c013009dc09d009cc09c003d003c0035002f009fccaac09f009ec09e006b00670039003300ff0100016b00000012001000000d7777772e62616964752e636f6d000b000403000102000a000c000a001d0017001e00190018337400000010000e000c02683208687474702f312e31001600000017000000310000000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602002b0009080304030303020301002d00020101003300260024001d00202ac995cfd440523c314e81183ac4e113ae27d34ac5bd47bf9720fce470acd15e001500a600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    verifyProtocol(s)
}

def run_parseServerHello() {
    def s = '16030300600200005c03035e09b3bdeba8e24059fbc0f3470161d0b6813426c7ff5ebb0167e6224e4ad6a5205549e9bf623581b257f458aed2a12a8513569696c3429a424a524c6217eddeb8c02f000014ff010001000010000b000908687474702f312e31'
    verifyProtocol(s)
}

def run_parseCertificate() {
    def s = '1603030e2d0b000e29000e260009b3308209af30820897a003020102020c2cee193c188278ea3e437573300d06092a864886f70d01010b05003066310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361313c303a06035504031333476c6f62616c5369676e204f7267616e697a6174696f6e2056616c69646174696f6e204341202d20534841323536202d204732301e170d3139303530393031323230325a170d3230303632353035333130325a3081a7310b300906035504061302434e3110300e060355040813076265696a696e673110300e060355040713076265696a696e6731253023060355040b131c73657276696365206f7065726174696f6e206465706172746d656e7431393037060355040a13304265696a696e67204261696475204e6574636f6d20536369656e636520546563686e6f6c6f677920436f2e2c204c7464311230100603550403130962616964752e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100b4c6bfda53200fea40f3b85217663b36018d12b4990dd39b6c1853b11908b0fa73473e0d3a796278612e543c497c56dac0be6155d542706a10bef5bd8d6496210093630987b719ba0e203e49c853ed028f4601eba1079373bbedf1b3c9e2fbddf0392a83adf44198bc86eaba74a8a6e3d0e5c58eb30bb2d2ac91740eff80102336626508b487f5570c25c700d8f5a85db83341a72a5fdbfa709e21bbae4216660769fe1c262a810fab73e3d65220a46da86cd46648a46ff2680ac565a14ebf047a40431cd375fb75ac19d64a35056ecfd565d144ca6b0c5804c4854f1fbe2c32d1f1c628fbf92636b56dfacb96a2a0d0bcf851df0744bd8f6f67c0d4afd9cdc30203010001a382061930820615300e0603551d0f0101ff0404030205a03081a006082b06010505070101048193308190304d06082b060105050730028641687474703a2f2f7365637572652e676c6f62616c7369676e2e636f6d2f6361636572742f67736f7267616e697a6174696f6e76616c73686132673272312e637274303f06082b060105050730018633687474703a2f2f6f637370322e676c6f62616c7369676e2e636f6d2f67736f7267616e697a6174696f6e76616c73686132673230560603551d20044f304d304106092b06010401a03201143034303206082b06010505070201162668747470733a2f2f7777772e676c6f62616c7369676e2e636f6d2f7265706f7369746f72792f3008060667810c01020230090603551d130402300030490603551d1f04423040303ea03ca03a8638687474703a2f2f63726c2e676c6f62616c7369676e2e636f6d2f67732f67736f7267616e697a6174696f6e76616c7368613267322e63726c308203490603551d11048203403082033c820962616964752e636f6d8212636c69636b2e686d2e62616964752e636f6d8210636d2e706f732e62616964752e636f6d82106c6f672e686d2e62616964752e636f6d82147570646174652e70616e2e62616964752e636f6d8210776e2e706f732e62616964752e636f6d82082a2e39312e636f6d820b2a2e6169706167652e636e820c2a2e6169706167652e636f6d820d2a2e61706f6c6c6f2e6175746f820b2a2e62616964752e636f6d820e2a2e62616964756263652e636f6d82122a2e6261696475636f6e74656e742e636f6d820e2a2e62616964757063732e636f6d82112a2e62616964757374617469632e636f6d820c2a2e6261696661652e636f6d820e2a2e626169667562616f2e636f6d820f2a2e6263652e62616964752e636f6d820d2a2e626365686f73742e636f6d820b2a2e6264696d672e636f6d820e2a2e62647374617469632e636f6d820d2a2e6264746a7263762e636f6d82112a2e626a2e62616964756263652e636f6d820d2a2e636875616e6b652e636f6d820b2a2e646c6e656c2e636f6d820b2a2e646c6e656c2e6f726782122a2e647565726f732e62616964752e636f6d82102a2e6579756e2e62616964752e636f6d82112a2e66616e79692e62616964752e636f6d82112a2e677a2e62616964756263652e636f6d82122a2e68616f3132332e62616964752e636f6d820c2a2e68616f3132332e636f6d820c2a2e68616f3232322e636f6d820e2a2e696d2e62616964752e636f6d820f2a2e6d61702e62616964752e636f6d820f2a2e6d62642e62616964752e636f6d820c2a2e6d697063646e2e636f6d82102a2e6e6577732e62616964752e636f6d820b2a2e6e756f6d692e636f6d82102a2e736166652e62616964752e636f6d820e2a2e736d617274617070732e636e82112a2e73736c322e6475617070732e636f6d820e2a2e73752e62616964752e636f6d820d2a2e7472757374676f2e636f6d82122a2e7875657368752e62616964752e636f6d820b61706f6c6c6f2e6175746f820a6261696661652e636f6d820c626169667562616f2e636f6d820664777a2e636e820f6d63742e792e6e756f6d692e636f6d820c7777772e62616964752e636e82107777772e62616964752e636f6d2e636e301d0603551d250416301406082b0601050507030106082b06010505070302301d0603551d0e0416041476b5e6d649f8f836ea75a96d5e4d555b375cfdc7301f0603551d2304183016801496de61f1bd1c1629531cc0cc7d3b830040e61a7c30820104060a2b06010401d6790204020481f50481f200f0007600bbd9dfbc1f8a71b593942397aa927b473857950aab52e81a909664368e1ed1850000016a9a2ee19a000004030047304502202c7b4dc0f985478a2d0ac0793bd6b4b566f8aafb8258ad2336fe16bca6839921022100c02fcd9c9920cb7d915fd28bc6131073b5c1540333419fa66ac51493cf692b6b0076006f5376ac31f03119d89900a45115ff77151c11d902c10029068db2089a37d9130000016a9a2ede4f000004030047304502200332689e39d0eb5f1961dba712696f28448102a53cc2a313d57e98265f201aa0022100a78b62b3b0b44432e211ff458d55112c36ab299344c8345cce7c355731aeab12300d06092a864886f70d01010b05000382010100aab9cd528edc365d47d48bf3321706468360a327054929b11b466e38fe93fe09436cd2a158241242b7ab41f8470a7d64b575dc5a4514b2a4186b9cb73b8fb37ed2bdc0724b3505ae0d2d191f5073725adf97183bdb2af3de44ce642dc11e84cc76243e30672326e84ff70bf6ec69d77f51a9a06fb8c414e2c04a4ac4005d576ac941c4252b3218aa62a81e4981731c815f5efae49432c3506d8eaacc6c4c530cfa8f4e34799fa560c0f85075b8a19d01e6ab25230c3b2402405824ff34028b946110682fb680e3d05f4a0aa702d2c0983e1de802c8277126b2a887b6db9d10474bc2136234c6d03c390939258ffea2f4f3fbdf9b273dfcd028e86ddcdd17d31f00046d3082046930820351a003020102020b040000000001444ef04247300d06092a864886f70d01010b05003057310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d73613110300e060355040b1307526f6f74204341311b301906035504031312476c6f62616c5369676e20526f6f74204341301e170d3134303232303130303030305a170d3234303232303130303030305a3066310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361313c303a06035504031333476c6f62616c5369676e204f7267616e697a6174696f6e2056616c69646174696f6e204341202d20534841323536202d20473230820122300d06092a864886f70d01010105000382010f003082010a0282010100c70e6c3f23937fcc70a59d20c30e533f7ec04ec29849ca47d523ef03348574c8a3022e465c0b7dc9889d4f8bf0f89c6c8c5535dbbff2b3eafbe356e74a46d91322ca36d59bc1a8e3964393f20cbce6f9e6e899c86348787f5736691a191d5ad1d47dc29cd47fe18012ae7aea88ea57d8ca0a0a3a1249a262197a0d24f737ebb473927b05239b12b5ceeb29dfa41402b901a5d4a69c436488def87efee3f51ee5fedca3a8e46631d94c25e918b9895909aee99d1c6d370f4a1e352028e2afd4218b01c445ad6e2b63ab926b610a4d20ed73ba7ccefe16b5db9f80f0d68b6cd908794a4f7865da92bcbe35f9b3c4f927804eff9652e60220e10773e95d2bbdb2f10203010001a382012530820121300e0603551d0f0101ff04040302010630120603551d130101ff040830060101ff020100301d0603551d0e0416041496de61f1bd1c1629531cc0cc7d3b830040e61a7c30470603551d200440303e303c0604551d20003034303206082b06010505070201162668747470733a2f2f7777772e676c6f62616c7369676e2e636f6d2f7265706f7369746f72792f30330603551d1f042c302a3028a026a0248622687474703a2f2f63726c2e676c6f62616c7369676e2e6e65742f726f6f742e63726c303d06082b060105050701010431302f302d06082b060105050730018621687474703a2f2f6f6373702e676c6f62616c7369676e2e636f6d2f726f6f747231301f0603551d23041830168014607b661a450d97ca89502f7d04cd34a8fffcfd4b300d06092a864886f70d01010b05000382010100462aee5ebdae0160373111867174b64649c81016fe2f622317ab1f87f882edcadf0e2cdf64758ee51872a78c3a8bc9aca57750f7ef9ea4e0a08f1457a32a5fec7e6d10e6ba8db00887760e4cb2d951bb1102f25cdd1cbdf355960fd406c0fce2238a2470d3bbf0791aa76170838aaf06c520d8a163d06cae4f32d7ae7c184575052977df4240646486be2a7609316f1d24f499d085fef22108f9c6f6f1d059edd6563c08280367baf0f9f1901647ae67e6bc8048e9427634975569240e83d6a02db4f5f3798a4928741a41a1c2d324883530609417b4e10422313d3b2f1706b2b89d862b5a69ef83f54bc4aab42af87ca1b185948cf40c870cf4ac40f8594998'

    verifyProtocol(s)
}

def verifyProtocol(String hexData) {
    def arr = HexUtils.parseHexString(hexData)
    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(arr)

    TLSRecord<?> record = SerializeUtils.readFrom(TLSRecord.class, byteArrayInputStream)

    println fieldsToJson(record)
    ByteArrayOutputStream bo = new ByteArrayOutputStream()
    SerializeUtils.writeTo(record, bo)
    def byteArray = bo.toByteArray()
    def s2 = HexUtils.getHexString(byteArray)
    assert s2 == hexData
}

def run_parseServerKeyExchange() {
    def s = '160303014d0c0001490300174104682ee37a8648254d49bca7366fde3707723d064dd0d793693d3277f3199a14c20410492fa14a8fff843a258bdb041dcddacff2773646a484ea2037378dfda386040101001f6ab602fda06922f9d79096ef07cd92964edbf9ead27537ffc987a40f0a7d5195ca3bbeb30dc5fb8986b7bab5e8361b6b35f1e612401bbac7ce17ec7d0c491558bf30fe2306f6d69ad94b54a61e6a85f761faabd0cd5d11975ac0d00b57b14866aaff34a294e13f5a1c410a38090b5adfec71ac7a34b843acea4b8f9e7b1ad55e9662c187354df21950d427778503b7ea4f18aedff16bef80bd9cb5ee380d7aa75aa463ba23b5e2dcaa4d9094822bef7eefc7faa225112054dbf03f0983b4d1a3bc46605056b240aad76fdf6324cbc8312b1eab8e944514dfe3667f6f3801f7ebe7c9cf1dddff7a03ba4276a03d365350e8bde4a2f96ac458315f1049e5e6bc'

    verifyProtocol(s)
}

def run_parseServerHelloDone() {
    def s = '16030300040e000000'

    verifyProtocol(s)
}

def run_parseChangeCipherSpec() {
    def s = '140303000101'

    verifyProtocol(s)
}

//run_fromHex()
//run_serialize()
run_parseClientHelloFromRaw()
run_parseServerHello()
run_parseCertificate()
run_parseServerKeyExchange()
run_parseServerHelloDone()
run_parseChangeCipherSpec()