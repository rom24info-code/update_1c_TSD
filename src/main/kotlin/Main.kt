
import com.jacob.activeX.ActiveXComponent
import com.jacob.com.Dispatch
import sun.net.ftp.FtpClient
import java.io.File
import java.io.FileOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.text.SimpleDateFormat
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.system.exitProcess


// Исключения
const val EXCEPT_DOWNLOAD_FILE = 100
const val EXCEPT_LOGOUT_USER_1C = 101
const val EXCEPT_LOAD_CONFIG_1C = 102
const val EXCEPT_UPDATE_CONFIG_1C = 103
const val EXCEPT_CONNECT_FTP = 104
const val EXCEPT_NO_VALID_CONFIG_FILE_APPLICATION = 105
const val EXCEPT_OS_NO_WINDOWS = 106
val LINE_SEPARATOR: String by lazy { System.getProperty("line.separator")}

// Константы
const val ROOT_DIRECTORY: String = "update_config_TSD"
const val UPDATE_FLAG: String = "updateFlag.txt"
const val MESSAGE_UPDATE: String = "Update"
const val MESSAGE_LOAD: String = "Load"
const val MESSAGE_DOWNLOAD:String = "Download"
const val DIRECTORY_LOG: String = "log"
const val SELF_UPDATER = "update_1c_TSD.jar"
const val VERSION = "0.0.2"
const val BOM = "\uFEFF"
const val SCHTASK_NAME = "updateTSD"
const val PASS_WIN = "XyIZLIyxXrq91Ktmi9SzlQ=="

// Имена параметров конфигурационного файла
const val PARAM_PATH_TO_1C = "pathTo1c"
const val PARAM_PARAMETERS_1C = "parametersForRun1c"
const val PARAM_NAME_BASE_1C = "nameBase1c"
const val PARAM_USER_1C = "user1c"
const val PARAM_PASSWORD_USER_1C = "pass1c"
const val PARAM_CRYPT_PASSWORD_USER_1C = "cryptPass1c"
const val PARAM_USER_FTP = "userFtp"
const val PARAM_PASSWORD_USER_FTP = "passFtp"
const val PARAM_CRYPT_PASSWORD_USER_FTP = "cryptPassFtp"
const val PARAM_PATH_LOCAL_FILES_FROM_FTP = "pathLocalFileFromFtp"
const val PARAM_USER_CLUSTER = "userCluster"
const val PARAM_PASS_CLUSTER = "passCluster"
const val PARAM_CRYPT_PASS_CLUSTER = "cryptPassCluster"
const val PARAM_FTP_HOST = "ftpHost"
const val PARAM_TIME_END_UPDATE = "timeEndUpdate"


val ftp: FtpClient by lazy { FtpClient.create() }

lateinit var username: String
lateinit var password: String
lateinit var remoteHost: String
var port: Int = 21

lateinit var fileNameUpdate: String
lateinit var dateToUpdate: Date

lateinit var config: Map<String, String>

object AESEncyption {

    const val secretKey = "tK5UTui+DPh8lIlBxya5XVsmeDCoUl6vHhdIESMB6sQ="
    const val salt = "QWlGNHNhMTJTQWZ2bGhpV3U=" // base64 decode => AiF4sa12SAfvlhiWu
    const val iv = "bVQzNFNhRkQ1Njc4UUFaWA==" // base64 decode => mT34SaFD5678QAZX

    fun encrypt(strToEncrypt: String) :  String?
    {
        try
        {
            val ivParameterSpec = IvParameterSpec(Base64.getDecoder().decode(iv))

            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
            val spec =  PBEKeySpec(secretKey.toCharArray(), Base64.getDecoder().decode(salt), 10000, 256)
            val tmp = factory.generateSecret(spec)
            val secretKey =  SecretKeySpec(tmp.encoded, "AES")

            val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec)
            val ch = cipher.doFinal(strToEncrypt.toByteArray(Charsets.UTF_8))
            return Base64.getEncoder().encodeToString(ch)
        }
        catch (e: Exception)
        {
            println("Error while encrypting: $e")
        }
        return null
    }

    fun decrypt(strToDecrypt : String) : String? {
        try
        {
            val ivParameterSpec =  IvParameterSpec(Base64.getDecoder().decode(iv))
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
            val spec =  PBEKeySpec(secretKey.toCharArray(), Base64.getDecoder().decode(salt), 10000, 256)
            val tmp = factory.generateSecret(spec)
            val secretKey =  SecretKeySpec(tmp.encoded, "AES")

            val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec)
            return  String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)))
        }
        catch (e : Exception)
        {
            println("Error while decrypting: $e")
        }
        return null
    }
}



fun main(args: Array<String>) {
// TODO: 05.04.2022 При скачивении файлов сначала скачивать во временный файл, а уж затем перезаписывать имеющийся.
//  Бывало некорректно скачивался.
    println("Version $VERSION")

//    val a = 0
//    val b = 300000
//    val random = (( Math.random() * (b-a) ) + a).toLong()
//    Thread.sleep(random)

    checkCreateSchedule()

    readConfigFile()

    username = config[PARAM_USER_FTP]!!
    password = config[PARAM_PASSWORD_USER_FTP]!!
    remoteHost = config[PARAM_FTP_HOST]!!

    if(selfUpdate()){
        putHostNameOnFtp()

        try {
            ftp.close()
        } catch (e: Exception) {

        }

        exitProcess(0)
    }

    putHostNameOnFtp()

    fileNameUpdate = getNameUpdateFile()
    dateToUpdate = getDateToUpdate1c()


    if (fileNameUpdate.trim() == "")
        exitProcess(0)

    val osName = System.getProperty("os.name").lowercase()
    var osArch = System.getProperty("os.arch").lowercase()

    if (!osName.contains("win")) {
        exitProcess(EXCEPT_OS_NO_WINDOWS)
    }

    if (osArch.contains("64")) {
        System.setProperty("jacob.dll.path", "${pathToSelfJarExecutable()}jacob-1.20-x64.dll")
    } else {
        System.setProperty("jacob.dll.path", "${pathToSelfJarExecutable()}jacob-1.20-x86.dll")
    }

    if (!validateConfig(config)) {
        println("Не корректный файл config.conf")
        exitProcess(EXCEPT_NO_VALID_CONFIG_FILE_APPLICATION)
    }

    if (isNeedDownloadUpdateFile()) {
        if (!downloadUpdateFile()) {
            exitProcess(EXCEPT_DOWNLOAD_FILE)
        }
    }

    if (theTimeHasGone())
        exitProcess(0)

    if (ifNeedLoadCfg()){
        val resultLoad = loadConfig1c()
        if (resultLoad != 0)
            exitProcess(resultLoad)
    }

    if (!ifNeedUpdate()) {
        exitProcess(0)
    } else {

        val resultUpdate = updateConf1c()
        if (resultUpdate != 0) {
            exitProcess(resultUpdate)
        }
    }

    try {
        ftp.close()
    } catch (e: Exception) {

    }
}

fun putHostNameOnFtp() {
    initFtpClient()
    ftp.putFileStream("$ROOT_DIRECTORY/hostNames/${getMagazine()} ${config[PARAM_NAME_BASE_1C]?.split("\\")?.get(1)?.trim()}").close()
}

fun checkCreateSchedule() {
    if (!File("${pathToSelfJarExecutable()}UpdateTSD.xml").exists())
        return

    val executeString = "Schtasks /Query /tn $SCHTASK_NAME /xml"
    val process = Runtime.getRuntime().exec(executeString)
    process.waitFor()
    val output = process.inputStream.reader().readText()
    if (output == "") {
        val executeString1 = "Schtasks /RU dixi\\1c8 /RP ${getPass(PASS_WIN)} /Create /tn $SCHTASK_NAME /xml ${pathToSelfJarExecutable()}UpdateTSD.xml"
        val process1 = Runtime.getRuntime().exec(executeString1)
        process1.waitFor()
        println(process1.inputStream.reader().readText())
    }
}

fun getPass(st: String): String {
    val pass = AESEncyption.decrypt(st)
    return pass!!
}

fun sendLogMessage(message: String) {
    // TODO: 17.02.2022 Сделать при недоступном фтп отложенную отправку лога
    initFtpClient()
    val format = SimpleDateFormat("ddMMyyyyHHmmss")
    val date = format.format(Date())
    val mag = getMagazine()
    val logMessage = "$date $mag $message $fileNameUpdate"
    ftp.putFileStream("$ROOT_DIRECTORY/log/$logMessage").close()

    val dirLog = File("${pathToSelfJarExecutable()}$DIRECTORY_LOG")
    if (!dirLog.exists())
        dirLog.mkdir()

    File("${pathToSelfJarExecutable()}$DIRECTORY_LOG\\$logMessage").createNewFile()
}

fun theTimeHasCome(): Boolean {
    return Date().after(dateToUpdate)
}

fun theTimeHasGone(): Boolean {
    val format = SimpleDateFormat()
    format.applyPattern("HH:mm:ss")
    val endTimeUpdate = format.parse(config[PARAM_TIME_END_UPDATE])
    val cal1 = GregorianCalendar()
    cal1.time = endTimeUpdate

    val cal = GregorianCalendar()
    cal.time = Date()
    cal.set(Calendar.HOUR_OF_DAY, cal1.get(Calendar.HOUR_OF_DAY))
    cal.set(Calendar.MINUTE, cal1.get(Calendar.MINUTE))
    cal.set(Calendar.SECOND, cal1.get(Calendar.SECOND))
    cal.set(Calendar.MILLISECOND, 0)
    val endDateToUpdate = cal.time


    return endDateToUpdate < Date()
}

fun selfUpdate(): Boolean {
    if (!needSelfUpdate())
        return false

//    if (!File("${pathToSelfJarExecutable()}\\updater.jar").exists()) {
        initFtpClient()
        val outStream = FileOutputStream("${pathToSelfJarExecutable()}updater.jar")
        ftp.getFile("${ROOT_DIRECTORY}/updater.jar", outStream)
        outStream.close()
//    }

    val executeCommandLoad =
        "java -jar ${pathToSelfJarExecutable()}updater.jar"
    Runtime.getRuntime().exec(executeCommandLoad)
    return true
}

fun needSelfUpdate(): Boolean {
    initFtpClient()
    var result = false
    val listFiles = ftp.nameList(ROOT_DIRECTORY)
    listFiles.reader().forEachLine {
        if (it == SELF_UPDATER) {
            result = true
        }
    }

    return result
}

fun validateConfig(mConfig: Map<String, String>): Boolean {

    mConfig.forEach {
        if (it.key == PARAM_USER_CLUSTER)
            return@forEach

        if (it.key == PARAM_PASS_CLUSTER
            || it.key == PARAM_PASSWORD_USER_1C
            || it.key == PARAM_PASSWORD_USER_FTP)
                return@forEach

        if (it.value.trim() == "")
            return false
    }
    return true
}

fun cryptPasswords() {
    val tempConfig = mutableMapOf<String, String>()
    config.forEach {
        tempConfig[it.key] = it.value
    }
    val passCluster = tempConfig[PARAM_PASS_CLUSTER]
    if (passCluster != null) {
        val encryptPassCluster = AESEncyption.encrypt(passCluster)!!
        tempConfig[PARAM_CRYPT_PASS_CLUSTER] = encryptPassCluster
    } else {
        val tempCluster = tempConfig[PARAM_CRYPT_PASS_CLUSTER]!!
        val decryptPassCluster = AESEncyption.decrypt(tempCluster)!!
        tempConfig[PARAM_PASS_CLUSTER] = decryptPassCluster
    }

    val pass1c = tempConfig[PARAM_PASSWORD_USER_1C]
    if (pass1c != null) {
        val encryptPass1c = AESEncyption.encrypt(pass1c)!!
        tempConfig[PARAM_CRYPT_PASSWORD_USER_1C] = encryptPass1c
    } else {
        val temp1c = tempConfig[PARAM_CRYPT_PASSWORD_USER_1C]!!
        val decryptPass1c = AESEncyption.decrypt(temp1c)!!
        tempConfig[PARAM_PASSWORD_USER_1C] = decryptPass1c
    }

    val passFtp = tempConfig[PARAM_PASSWORD_USER_FTP]
    if (passFtp != null) {
        val encryptPassFtp = AESEncyption.encrypt(passFtp)!!
        tempConfig[PARAM_CRYPT_PASSWORD_USER_FTP] = encryptPassFtp
    }
    else {
        val tempFtp = tempConfig[PARAM_CRYPT_PASSWORD_USER_FTP]!!
        val decryptPassFtp = AESEncyption.decrypt(tempFtp)!!
        tempConfig[PARAM_PASSWORD_USER_FTP] = decryptPassFtp
    }

    config = tempConfig.toMap()

    writeConfigFile()
}

fun writeConfigFile() {
    val pathToConfig = pathToSelfJarExecutable() + "config.conf"
    val configFile = File(pathToConfig)
    val fOutStream = FileOutputStream(configFile)
    config.forEach {
        if (it.key == PARAM_PASS_CLUSTER && it.value.trim() != "")
            return@forEach
        if (it.key == PARAM_PASSWORD_USER_1C && it.value.trim() != "")
            return@forEach
        if (it.key == PARAM_PASSWORD_USER_FTP && it.value.trim() != "")
            return@forEach
        fOutStream.write("${it.key.trim()}=${it.value.trim()}$LINE_SEPARATOR".toByteArray())
    }
    fOutStream.close()
}

fun readConfigFile() {
    val pathToConfig = pathToSelfJarExecutable() + "config.conf"
    val configFile = File(pathToConfig)
    if (!configFile.exists()) {
        configFile.createNewFile()
        fillConfigFile(configFile)
    }

    val tempConf: MutableMap<String, String> = mutableMapOf()
    var lineFile: String
    configFile.forEachLine {
        lineFile = if (it.startsWith(BOM))
            it.substring(1)
        else
            it

        val tempList = lineFile.trim().split("=")
        var valueParam = ""
        tempList.forEachIndexed { index, value ->
            if (index == 0)
                    return@forEachIndexed
            valueParam += value
        }
        tempConf[tempList[0].trim()] = valueParam
        println("${tempList[0].trim()}=$valueParam")
    }
    config = tempConf.toMap()
    cryptPasswords()
}

fun fillConfigFile(configFile: File) {
    val configMap: MutableMap<String, String> = mutableMapOf()
    configMap[PARAM_PARAMETERS_1C] = ""
    configMap[PARAM_PATH_TO_1C] = ""
    configMap[PARAM_NAME_BASE_1C] = ""
    configMap[PARAM_USER_CLUSTER] = ""
    configMap[PARAM_PASS_CLUSTER] = ""
    configMap[PARAM_USER_1C] = ""
    configMap[PARAM_PASSWORD_USER_1C] = ""
    configMap[PARAM_USER_FTP] = ""
    configMap[PARAM_PASSWORD_USER_FTP] = ""
    configMap[PARAM_PATH_LOCAL_FILES_FROM_FTP] = ""
    configMap[PARAM_FTP_HOST] = ""
    configMap[PARAM_TIME_END_UPDATE] = "05:00:00"

    val fOutStream = FileOutputStream(configFile)
    configMap.forEach {
        fOutStream.write("${it.key} = ${it.value}$LINE_SEPARATOR".toByteArray())
    }
    fOutStream.close()
}

fun loadConfig1c(): Int {
    if (!logOut1cUsers()) {
        sendLogMessage(EXCEPT_LOGOUT_USER_1C.toString())
        return EXCEPT_LOGOUT_USER_1C
    }

    // Загрузка и сохранение конфигурации
    val executeCommandLoad =
        "cmd /c ${config[PARAM_PATH_TO_1C]}" +
                " ${config[PARAM_PARAMETERS_1C]}" +
                " /S ${config[PARAM_NAME_BASE_1C]}" +
                " /N ${config[PARAM_USER_1C]}" +
                " /P ${config[PARAM_PASSWORD_USER_1C]}" +
                " /LoadCfg ${pathToSelfJarExecutable()}${fileNameUpdate}"
    println(executeCommandLoad)
    val processLoad = Runtime.getRuntime().exec(executeCommandLoad)
    processLoad.waitFor()

    if (!processLoad.isAlive) {
        if (processLoad.exitValue() != 0) {
            sendLogMessage(EXCEPT_LOAD_CONFIG_1C.toString())
            return EXCEPT_LOAD_CONFIG_1C
        }
    } else
        return 200

    sendLogMessage("LOAD")
    File("${pathToSelfJarExecutable()}${getNameUpdateFile()}").delete()
    return 0
}

fun updateConf1c(): Int {
    if (!logOut1cUsers()) {
        sendLogMessage(EXCEPT_LOGOUT_USER_1C.toString())
        return EXCEPT_LOGOUT_USER_1C
    }

    // Обновление конфигурации
    val executeCommandUpdate =
        "cmd /c ${config[PARAM_PATH_TO_1C]}" +
                " ${config[PARAM_PARAMETERS_1C]}" +
                " /S ${config[PARAM_NAME_BASE_1C]}" +
                " /N ${config[PARAM_USER_1C]}" +
                " /P ${config[PARAM_PASSWORD_USER_1C]}" +
                " /UpdateDBCfg -WarningsAsErrors"
    config[PARAM_PARAMETERS_1C]
    val processUpdate = Runtime.getRuntime().exec(executeCommandUpdate)
    processUpdate.waitFor()

    if (!processUpdate.isAlive) {
        if (processUpdate.exitValue() != 0) {
            sendLogMessage(EXCEPT_LOAD_CONFIG_1C.toString())
            return EXCEPT_UPDATE_CONFIG_1C
        }
    } else
        return 200

    sendLogMessage("UPDATE")
    return 0
}

fun downloadUpdateFile(): Boolean {
    initFtpClient()
    val fileName = fileNameUpdate
    return try {

        val dir = File(pathToSelfJarExecutable())
        if (!dir.exists())
            dir.mkdir()

        val file = File(pathToSelfJarExecutable() + fileName)
        val outStream = FileOutputStream(file)

        ftp.getFile("/$ROOT_DIRECTORY/$fileName", outStream)
        outStream.close()
        sendLogMessage("Download")
        true

    } catch (e: Exception) {
        false
    }
}

fun ifNeedUpdate(): Boolean {
    if (!theTimeHasCome())
        return false

    val logMessage = File("${pathToSelfJarExecutable()}$DIRECTORY_LOG")
    logMessage.list().forEach {
        val spl = it.split(" ")
        if (spl.size != 4)
            return@forEach
        val fileConfig = spl[3]
        val message = spl[2]
        if (fileConfig.trim().lowercase() == fileNameUpdate.lowercase()) {
            if (message.trim().lowercase() == MESSAGE_UPDATE.lowercase()) {
                return false
            }
        }
    }

    return true
}

fun ifNeedLoadCfg(): Boolean {
    if (!theTimeHasCome())
        return false

    val logMessage = File("${pathToSelfJarExecutable()}$DIRECTORY_LOG")
    logMessage.list().forEach {
        val spl = it.split(" ")
        if (spl.size != 4)
            return@forEach
        val fileConfig = spl[3]
        val message = spl[2]
        if (fileConfig.trim().lowercase() == fileNameUpdate.lowercase()) {
            if (message.trim().lowercase() == MESSAGE_LOAD.lowercase()) {
                return false
            }
        }
    }

    return true
}

fun getNameUpdateFile(): String {
    initFtpClient()

    var fileName = ""
    val listFiles = ftp.nameList(ROOT_DIRECTORY)
    listFiles.reader().forEachLine {
        if (it == UPDATE_FLAG) {
            val stream = ftp.getFileStream("/$ROOT_DIRECTORY/$UPDATE_FLAG")
            stream.reader().forEachLine { it1 ->
                val params = it1.split(";")
                if (params[0].trim().lowercase() == getMagazine().trim().lowercase())
                    fileName = params[2].trim()
            }
        }
    }

    return fileName
}

fun getDateToUpdate1c(): Date {
    initFtpClient()

    var dateUpdate = Date(0)
    val listFiles = ftp.nameList(ROOT_DIRECTORY)
    listFiles.reader().forEachLine {
        if (it == UPDATE_FLAG) {
            val stream = ftp.getFileStream("/$ROOT_DIRECTORY/$UPDATE_FLAG")
            stream.reader().forEachLine { it1 ->
                val params = it1.split(";")
                if (params[0].trim().lowercase() == getMagazine().trim().lowercase()) {
                    val format = SimpleDateFormat()
                    format.applyPattern("dd.MM.yyyy HH:mm:ss")
                    dateUpdate = format.parse(params[1].trim())
                }
            }
        }
    }

    return dateUpdate
}

fun initFtpClient() {

    val reconnect = try {
        ftp.features
        false
    } catch (e: java.lang.Exception) {
        true
    }

    if (reconnect) {
        try {
            ftp.connect(InetSocketAddress(remoteHost, port))
            ftp.login(username, password.toCharArray())
            ftp.enablePassiveMode(true)
        } catch (e: Exception) {
            println(e.message)
            exitProcess(EXCEPT_CONNECT_FTP)
        }
    }
}

fun getMagazine(): String {
    return InetAddress.getLocalHost().hostName
}

fun logOut1cUsers(): Boolean {

    try {
        val serverName = config[PARAM_NAME_BASE_1C]?.split("\\")?.get(0)?.trim()
        val baseName = config[PARAM_NAME_BASE_1C]?.split("\\")?.get(1)?.trim()
        val userCluster = config[PARAM_USER_CLUSTER]?.trim()
        val passCluster = config[PARAM_PASS_CLUSTER]?.trim()
        println("$serverName, $baseName, $userCluster, $passCluster")

        val v8App = ActiveXComponent("v83.ComConnector")
        println("Получен v83.ComConnector!")

        val agent1c = Dispatch.call(v8App, "ConnectAgent", serverName).dispatch
        println("Получен агент!")
        val clusters = Dispatch.call(agent1c, "GetClusters").toSafeArray().toVariantArray()
        println("Получены кластеры!")
        clusters.forEach { cluster ->
            Dispatch.call(agent1c, "Authenticate", cluster, userCluster, passCluster)
            val infoBases = Dispatch.call(agent1c, "GetInfoBases", cluster).toSafeArray().toVariantArray()
            infoBases.forEach { infoBase ->
                if (Dispatch.get(infoBase.dispatch, "Name").string.uppercase() != baseName?.uppercase())
                    return@forEach
                println("Завершение сеансов пользователей " + Dispatch.get(infoBase.dispatch, "Name").string)
                val sessions = Dispatch.call(agent1c, "GetInfoBaseSessions", cluster, infoBase)
                    .toSafeArray()
                    .toVariantArray()
                sessions.forEach { session ->
                    println("   ${Dispatch.get(session.dispatch, "UserName")}")
                    Dispatch.call(agent1c, "TerminateSession", cluster, session)
                }
            }
        }
    } catch (e: java.lang.Exception) {
        println(e.message)
        return false
    }

    return true
}

fun isNeedDownloadUpdateFile(): Boolean {
    val logMessage = File("${pathToSelfJarExecutable()}$DIRECTORY_LOG")
    val workDir = File(pathToSelfJarExecutable())
    if (!workDir.exists())
        workDir.mkdir()
    if (!logMessage.exists())
        logMessage.mkdir()
    logMessage.list().forEach {
        val spl = it.split(" ")
        if (spl.size != 4)
            return@forEach
        val fileConfig = spl[3]
        val message = spl[2]
        if (fileConfig.trim().lowercase() == fileNameUpdate.lowercase()) {
            if (message.trim().lowercase() == MESSAGE_DOWNLOAD.lowercase()) {
                return false
            }
        }
    }

    return true
}

fun pathToSelfJarExecutable(): String {
    return File("").absolutePath + "\\"
}