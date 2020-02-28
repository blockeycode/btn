package org.btn.common

import io.netty.buffer.Unpooled
import io.netty.util.CharsetUtil
import java.math.BigInteger
import java.security.*
import java.security.spec.EncodedKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec


const val RSA_ALG = "RSA/ECB/PKCS1Padding"
const val AES_ALG = "AES/ECB/PKCS5padding" //notice must be set for different vm
private const val RSA_KF = "RSA"
private const val SHA_KEY = "SHA-1"
private const val KEYSIZE = 2048


fun aesEnc(s:String):Pair<ByteArray,ByteArray>{
    val generator = KeyGenerator.getInstance("AES")
    generator.init(128) // The AES key size in number of bits
    val aesKey = generator.generateKey()
    val aesCipher = Cipher.getInstance(AES_ALG)
    aesCipher.init(Cipher.ENCRYPT_MODE, aesKey)
    //notice encrypt with aes eky and convert to base 64
    val aesBytes = aesCipher.doFinal(s.toByteArray())
    return Pair(aesKey.encoded,aesBytes)
}
fun aesDec(key:ByteArray,data:ByteArray):String?{
    val aesKey = SecretKeySpec(key, "AES")
    val cipher = Cipher.getInstance(AES_ALG)
    cipher.init(Cipher.DECRYPT_MODE, aesKey)

    //notice decode with aes
    val token = String(cipher.doFinal(data))
    return token
}
fun base64Dec(s:String):ByteArray{
    val buf = Unpooled.wrappedBuffer(s.toByteArray(CharsetUtil.US_ASCII))
    val buf1 = io.netty.handler.codec.base64.Base64.decode(buf)
    val bytes = ByteArray(buf1.readableBytes())
    buf1.readBytes(bytes)
    buf1.release()
    buf.release()
    return bytes
}

fun base64Enc(bytes:ByteArray?):String{
    val buf = Unpooled.wrappedBuffer(bytes)
    val buf1 = io.netty.handler.codec.base64.Base64.encode(buf, 0,buf.readableBytes(),false)
    val s = buf1.toString(CharsetUtil.US_ASCII)
    buf1.release()
    buf.release()
    return s
}

private fun getRsaKey(bytes:ByteArray?,isPub:Boolean): Key {
    lateinit var keySpec: EncodedKeySpec
    val keyFactory = KeyFactory.getInstance(RSA_KF)
    return if(isPub){
        keySpec = X509EncodedKeySpec(bytes)
        val k = keyFactory.generatePublic(keySpec)
        k
    }else{
        keySpec = PKCS8EncodedKeySpec(bytes)
        keyFactory.generatePrivate(keySpec)
    }
}



fun sign(privBytes:ByteArray?,data:ByteArray):ByteArray{
    return rsaEncrypt(privBytes,data)
}

fun rsaEncrypt(privBytes:ByteArray?,data:ByteArray, keyIsPub:Boolean = false):ByteArray{
    val key = getRsaKey(privBytes,keyIsPub)
    val cipher = Cipher.getInstance(RSA_ALG)
    cipher.init(Cipher.ENCRYPT_MODE, key)
    return cipher.doFinal(data)
}

fun rsaDecrypt(pubBytes:ByteArray?, data:ByteArray, keyIsPub:Boolean = true):ByteArray{
    val key = getRsaKey(pubBytes,keyIsPub)
    val cipher = Cipher.getInstance(RSA_ALG)
    cipher.init(Cipher.DECRYPT_MODE, key)
    val dec = cipher.doFinal(data)
    return dec
}

fun rsaKeyPair(): KeyPair? {
    val mslog = BtnLog("BinaryKP")
    mslog.info("start")
    val secureRandom = SecureRandom()
    val keyPairGenerator = KeyPairGenerator.getInstance(RSA_KF)
    keyPairGenerator.initialize(KEYSIZE, secureRandom)
    val keyPair = keyPairGenerator.generateKeyPair()
    return keyPair
}

fun tailZeroCount(hash: ByteArray): Int {
    val bigInt = BigInteger(hash)
    println(bigInt.toString(2))
    val count = bigInt.lowestSetBit
    return count
}


private val bound = 10000000
fun randomInt():Int{
    return Random().nextInt(bound)%bound + bound
}


fun hash(data:ByteArray):ByteArray{
    val md = MessageDigest.getInstance(SHA_KEY)
    val hash = md.digest(data)
    return hash
}

@ExperimentalUnsignedTypes
@ExperimentalStdlibApi
fun leadingZeroCount(hash: ByteArray): Int {
    var count = 0
    val zero:Byte = 0
    var curByte:UByte = 0xffu
    for ((index, b) in hash.withIndex()){
        if(b == zero)
            count += 8
        else{
            curByte = b.toUByte()
            break
        }
    }
    return count + curByte.countLeadingZeroBits()
}

@ExperimentalUnsignedTypes
@ExperimentalStdlibApi
fun test(i:Int):Int{
    val arr = i.toString().toByteArray()
    val hash = hash(arr)
    val count = leadingZeroCount(hash)

    if(count > 20){
        println(i)
        val s = BigInteger(hash).toString(2)
        println("leading zero count="+count)
    }
    return count
}

@ExperimentalStdlibApi
@ExperimentalUnsignedTypes
fun test1(){
    val zero = 0x00
    val b1:UByte = 0x10u
    val b3:UByte = 0x03u
    val b7:UByte = 0x07u
    val bn:UByte = 0xffu

    println(b1.countLeadingZeroBits())
    println(b3.countLeadingZeroBits())
    println(b7.countLeadingZeroBits())
    println(bn.countLeadingZeroBits())
//    for(i in -127..127){
//        println("i="+i+" hex="+i.toString(16)+" bin="+i.toString(2))
//    }
}
@ExperimentalUnsignedTypes
@ExperimentalStdlibApi
fun main(){
    var totalNumber = 0
    for(i in 1..10000000){
        val count = test(i)
        if(count > 20)
            totalNumber ++
    }
    print("total number="+totalNumber)
}