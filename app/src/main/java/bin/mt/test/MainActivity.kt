package bin.mt.test

import android.annotation.SuppressLint
import android.app.Activity
import android.app.Application
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.util.Log
import android.util.Log.e
import android.widget.TextView
import bin.mt.signature.KillerApplication
import bin.mt.test.MainActivity.Companion.append
import bin.mt.test.MainActivity.Companion.openAt
import java.io.FileInputStream
import java.io.InputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Enumeration
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream
class App : Application() {
    init {
        KillerApplication() // 注释掉这句即可关闭过签
    }
}
open class MainActivity : Activity() {


    @SuppressLint("SetTextI18n") override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val msg = findViewById<TextView>(R.id.msg)

        // 以下演示了三种获取签名MD5的方式
        val signatureExpected = "3bf8931788824c6a1f2c6f6ff80f6b21"//原始签名MD5
        val signatureFromAPI = md5(signatureFromAPI())
        val signatureFromAPK = md5(signatureFromAPK())
        val signatureFromSVC = md5(signatureFromSVC())
        val signatureFromSVCNative = md5(svc(this))

        // 开启过签后，API与APK方式会获取到虚假的签名MD5

        // 而SVC方式总是能获取到真实的签名MD5
        val sb = SpannableStringBuilder()
        append(sb, "Expected: ", signatureExpected, Color.BLACK)
        append(sb, "From API: ", signatureFromAPI, if (signatureExpected == signatureFromAPI) Color.BLUE else Color.RED)
        append(sb, "From APK: ", signatureFromAPK, if (signatureExpected == signatureFromAPK) Color.BLUE else Color.RED)
        append(sb, "From SVC: ", signatureFromSVC, if (signatureExpected == signatureFromSVC) Color.BLUE else Color.RED)
        append(sb, "From SVC_native: ", signatureFromSVCNative, if (signatureExpected == signatureFromSVCNative) Color.BLUE else Color.RED)

        // 当然SVC并非绝对安全，只是相对而言更加可靠，实际运用还需结合更多的手段
        msg.setText(sb)

        svce(this)
    }

    @Throws(RuntimeException::class)
    private fun signatureFromAPI(): ByteArray? {
        try {
            @SuppressLint("PackageManagerGetSignatures")
            val info = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
            return info?.signatures?.getOrNull(0)?.toByteArray()
        } catch (e: PackageManager.NameNotFoundException) {
            throw RuntimeException(e)
        }
    }

    private fun signatureFromAPK(): ByteArray? {
        try {
            ZipFile(packageResourcePath).use { zipFile ->
                val entries: Enumeration<out ZipEntry> = zipFile.entries()
                while (entries.hasMoreElements()) {
                    val entry: ZipEntry = entries.nextElement()
                    if (entry.getName().matches("(META-INF/.*)\\.(RSA|DSA|EC)".toRegex())) {
                        val ips: InputStream? = zipFile.getInputStream(entry)
                        val certFactory = CertificateFactory.getInstance("X509")
                        val x509Cert = certFactory.generateCertificate(ips) as X509Certificate
                        return x509Cert.getEncoded()
                    }
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    private fun signatureFromSVC(): ByteArray? {
        try {
            ParcelFileDescriptor.adoptFd(openAt(packageResourcePath)).use { fd ->
                ZipInputStream(FileInputStream(fd.fileDescriptor)).use { zis ->
                    var entry: ZipEntry?
                    while ((zis.getNextEntry().also { entry = it }) != null) {
                        if (entry!!.getName().matches("(META-INF/.*)\\.(RSA|DSA|EC)".toRegex())) {
                            val certFactory = CertificateFactory.getInstance("X509")
                            val x509Cert = certFactory.generateCertificate(zis) as X509Certificate
                            return x509Cert.encoded
                        }
                    }
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }


    private fun md5(bytes: ByteArray?): String {
        if (bytes == null) {
            return "null"
        }
        try {
            val digest = MessageDigest.getInstance("MD5").digest(bytes)
            if (true) return BigInteger(1, digest).toString(16).padStart(32, '0')
            val hexDigits = "0123456789abcdef"
            val str = CharArray(digest.size * 2)
            var k = 0
            for (b in digest) {
                str[k++] = hexDigits.get(b.toInt() ushr 4 and 0xf)
                str[k++] = hexDigits.get(b.toInt() and 0xf)
            }
            return String(str)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        }
    }

    companion object {
        init {
            System.loadLibrary("test")
        }

        private fun append(sb: SpannableStringBuilder, header: String?, value: String?, color: Int) {
            val start = sb.length
            sb.append(header).append(value).append("\n")
            val end = sb.length
            sb.setSpan(ForegroundColorSpan(color), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            Log.d("svc", "$header:$value")
        }

        @JvmStatic external fun openAt(path: String?): Int
        @JvmStatic external fun svc(context: Context?): ByteArray?
        @JvmStatic external fun svce(context: Context?): Int
    }
}