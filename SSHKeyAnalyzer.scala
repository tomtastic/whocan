#!/usr/bin/env scala

import java.io.File
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Base64
import scala.io.Source
import scala.util.{Try, Success, Failure}

object SSHKeyAnalyzer {
  val VERSION = "0.65-scala"

  case class Config(
    filename: String = "",
    showMd5: Boolean = false,
    debug: Boolean = false
  )

  case class KeyInfo(
    line: Int,
    keyType: String,
    modBits: Int,
    exponent: String,
    fpMd5: String,
    fpSha256: String,
    comment: String,
    typeVer: String = "",
    failed: Boolean = false
  )

  def main(args: Array[String]): Unit = {
    val config = parseArgs(args)

    if (config.filename.isEmpty) {
      printUsage()
      sys.exit(1)
    }

    analyzeKeyFile(config)
  }

  def parseArgs(args: Array[String]): Config = {
    var config = Config()
    var i = 0

    while (i < args.length) {
      args(i) match {
        case "-h" | "--help" | "-?" | "-v" =>
          printInfo()
          printUsage()
          sys.exit(0)
        case "--md5" =>
          config = config.copy(showMd5 = true)
        case "-d" | "--debug" =>
          config = config.copy(debug = true)
        case other =>
          if (config.filename.isEmpty) {
            config = config.copy(filename = other)
          }
      }
      i += 1
    }

    config
  }

  def analyzeKeyFile(config: Config): Unit = {
    val file = new File(config.filename)
    if (!file.exists()) {
      println(s"Error: File not found: ${config.filename}")
      sys.exit(1)
    }

    var headerPrinted = false

    Try(Source.fromFile(file)) match {
      case Success(source) =>
        try {
          source.getLines().zipWithIndex.foreach { case (line, idx) =>
            val lineNum = idx + 1
            val trimmed = line.trim

            // Skip empty lines and comments
            if (trimmed.nonEmpty && !trimmed.startsWith("#")) {
              val keyInfoOpt = parseLine(trimmed, lineNum, config)

              keyInfoOpt.foreach { keyInfo =>
                if (!headerPrinted) {
                  printHeader(config)
                  headerPrinted = true
                }
                printKeyInfo(keyInfo, config)
              }
            }
          }
          } finally {
            source.close()
          }
      case Failure(exception) =>
        println(s"Error reading file: ${exception.getMessage}")
        sys.exit(1)
    }
  }

  def parseLine_bad(line: String, lineNum: Int, config: Config): Option[KeyInfo] = {
    // Extract key string and comment
    val keyPattern = """([a-zA-Z0-9+=\/]{65,})\s*(.*)$""".r

    keyPattern.findFirstMatchIn(line) match {
      case Some(m) =>
        val keyString = m.group(1)
        val comment = m.group(2)

        // Check if it looks like SSH-1 key
        if (keyString.matches(".*[0-9]{30,}.*")) {
          Some(KeyInfo(
            line = lineNum,
            keyType = "ssh-1",
            modBits = 0,
            exponent = "n/a",
            fpMd5 = "not_implemented",
            fpSha256 = "not_implemented",
            comment = comment,
            failed = true
          ))
        } else {
          decodePublicKey(keyString, lineNum, comment, config)
        }
      case None =>
        None
    }
  }

  def parseLine(line: String, lineNum: Int, config: Config): Option[KeyInfo] = {
    // Split line into fields
    val fields = line.trim.split("\\s+")

    if (fields.length < 2) {
      return None
    }

    // Detect known_hosts format: hostname/IP keytype keydata
    // vs authorized_keys format: keytype keydata [comment]
    val isKnownHostsFormat = !fields(0).matches("ssh-.*|ecdsa-.*|sk-.*") && 
                              fields.length >= 3 && 
                              fields(1).matches("ssh-.*|ecdsa-.*|sk-.*")

    val (keyType, keyData, comment) = if (isKnownHostsFormat) {
      // known_hosts format: hostname keytype keydata
      val hostname = fields(0)
      (fields(1), fields(2), hostname)
    } else if (fields(0).matches("ssh-.*|ecdsa-.*|sk-.*")) {
      // authorized_keys format: keytype keydata [comment]
      (fields(0), fields(1), if (fields.length > 2) fields.drop(2).mkString(" ") else "")
    } else if (fields.length >= 3 && fields(1).matches("ssh-.*|ecdsa-.*|sk-.*")) {
      // authorized_keys with options: options keytype keydata [comment]
      (fields(1), fields(2), if (fields.length > 3) fields.drop(3).mkString(" ") else "")
    } else {
      // Try to find ssh key type in the line
      val sshTypeIdx = fields.indexWhere(_.matches("ssh-.*|ecdsa-.*|sk-.*"))
      if (sshTypeIdx >= 0 && sshTypeIdx + 1 < fields.length) {
        (fields(sshTypeIdx), fields(sshTypeIdx + 1), 
          if (fields.length > sshTypeIdx + 2) fields.drop(sshTypeIdx + 2).mkString(" ") else "")
      } else {
        return None
      }
    }

    // Check if it looks like SSH-1 key (old format with numbers)
    if (keyData.matches(".*[0-9]{30,}.*")) {
      Some(KeyInfo(
        line = lineNum,
        keyType = "ssh-1",
        modBits = 0,
        exponent = "n/a",
        fpMd5 = "not_implemented",
        fpSha256 = "not_implemented",
        comment = comment,
        failed = true
      ))
    } else {
      decodePublicKey(keyData, lineNum, comment, config)
    }
  }

  def decodePublicKey(keyString: String, lineNum: Int, comment: String, config: Config): Option[KeyInfo] = {
    Try {
      val bytes = Base64.getDecoder.decode(keyString)
      val buffer = ByteBuffer.wrap(bytes)

      // Compute fingerprints
      val fpMd5 = computeMd5Fingerprint(bytes)
      val fpSha256 = computeSha256Fingerprint(bytes)

      // Read type length
      val typeLen = buffer.getInt()

      if (typeLen <= 1 || typeLen >= 20) {
        throw new Exception("Invalid key type length")
      }

      // Read key type
      val typeBytes = new Array[Byte](typeLen)
      buffer.get(typeBytes)
      val keyType = new String(typeBytes, "UTF-8")

      if (config.debug) {
        println(s"DEBUG: Key type: $keyType")
      }

      // Parse based on key type
      keyType match {
        case t if t.contains("rsa") =>
          parseRsaKey(buffer, keyType, lineNum, comment, fpMd5, fpSha256, config)
        case t if t.contains("dss") =>
          parseDssKey(buffer, keyType, lineNum, comment, fpMd5, fpSha256, config)
        case t if t.contains("ecdsa") =>
          parseEcdsaKey(buffer, keyType, lineNum, comment, fpMd5, fpSha256, config)
        case t if t.contains("ed25519") =>
          parseEd25519Key(buffer, keyType, lineNum, comment, fpMd5, fpSha256, config)
        case t if t.contains("sk-") =>
          // Security key variants (sk-ecdsa-sha2-nistp256@openssh.com, sk-ssh-ed25519@openssh.com)
          if (t.contains("ecdsa")) {
            parseEcdsaSkKey(buffer, keyType, lineNum, comment, fpMd5, fpSha256, config)
          } else if (t.contains("ed25519")) {
            parseEd25519SkKey(buffer, keyType, lineNum, comment, fpMd5, fpSha256, config)
          } else {
            throw new Exception(s"Unknown SK key type: $keyType")
          }
        case _ =>
          throw new Exception(s"Unknown key type: $keyType")
      }
  }.toOption.flatten.orElse {
    Some(KeyInfo(
      line = lineNum,
      keyType = "n/a",
      modBits = 0,
      exponent = "n/a",
      fpMd5 = "could_not_decode",
      fpSha256 = "could_not_decode",
      comment = comment,
      failed = true
    ))
  }
  }

  def parseRsaKey_bad(buffer: ByteBuffer, keyType: String, lineNum: Int, comment: String, 
    fpMd5: String, fpSha256: String, config: Config): Option[KeyInfo] = {
      // RSA: exponent then modulus
      val expLen = buffer.getInt()
      val expBytes = new Array[Byte](expLen)
      buffer.get(expBytes)
      val exponent = BigInt(1, expBytes).toString(10)

      val modLen = buffer.getInt()
      val modBits = (modLen - 1) * 8

      Some(KeyInfo(
        line = lineNum,
        keyType = keyType,
        modBits = modBits,
        exponent = exponent,
        fpMd5 = fpMd5,
        fpSha256 = fpSha256,
        comment = comment,
        typeVer = "1"
      ))
  }

  def parseRsaKey(buffer: ByteBuffer, keyType: String, lineNum: Int, comment: String,
    fpMd5: String, fpSha256: String, config: Config): Option[KeyInfo] = {
      try {
        // RSA: exponent then modulus
        val expLen = buffer.getInt()
        if (config.debug) {
          println(s"DEBUG: RSA expLen=$expLen, buffer remaining=${buffer.remaining()}")
        }

        val expBytes = new Array[Byte](expLen)
        buffer.get(expBytes)
        val exponent = BigInt(1, expBytes).toString(10)

        val modLen = buffer.getInt()
        if (config.debug) {
          println(s"DEBUG: RSA modLen=$modLen, buffer remaining=${buffer.remaining()}")
        }

        val modBytes = new Array[Byte](modLen)
        buffer.get(modBytes)
        val modulus = BigInt(1, modBytes)
        val modBits = modulus.bitLength

        if (config.debug) {
          println(s"DEBUG: RSA successful - modBits=$modBits")
        }

        Some(KeyInfo(
          line = lineNum,
          keyType = keyType,
          modBits = modBits,
          exponent = exponent,
          fpMd5 = fpMd5,
          fpSha256 = fpSha256,
          comment = comment,
          typeVer = "1"
        ))
      } catch {
        case e: Exception =>
          if (config.debug) {
            println(s"DEBUG: RSA parse failed - ${e.getClass.getSimpleName}: ${e.getMessage}")
            e.printStackTrace()
          }
          None
      }
  }

  def parseDssKey(buffer: ByteBuffer, keyType: String, lineNum: Int, comment: String,
    fpMd5: String, fpSha256: String, config: Config): Option[KeyInfo] = {
      try {
        // DSA/DSS: p, q, g, y (public key components)
        // Read p (prime modulus)
        val pLen = buffer.getInt()
        val pBytes = new Array[Byte](pLen)
        buffer.get(pBytes)
        val p = BigInt(1, pBytes)
        val modBits = p.bitLength

        Some(KeyInfo(
          line = lineNum,
          keyType = keyType,
          modBits = modBits,
          exponent = "n/a",
          fpMd5 = fpMd5,
          fpSha256 = fpSha256,
          comment = comment,
          typeVer = "2"
        ))
      } catch {
        case e: Exception =>
          if (config.debug) {
            println(s"DEBUG: DSS parse failed - ${e.getClass.getSimpleName}: ${e.getMessage}")
          }
          None
      }
  }

  def parseEcdsaKey(buffer: ByteBuffer, keyType: String, lineNum: Int, comment: String,
    fpMd5: String, fpSha256: String, config: Config): Option[KeyInfo] = {
      try {
        // ECDSA: curve name, then public key point
        val curveLen = buffer.getInt()
        val curveBytes = new Array[Byte](curveLen)
        buffer.get(curveBytes)
        val curveName = new String(curveBytes, "UTF-8")

        // Determine bit size from curve name
        val modBits = curveName match {
          case "nistp256" => 256
          case "nistp384" => 384
          case "nistp521" => 521
          case _ => 
            // Fallback: try to extract from key type (e.g., "ecdsa-sha2-nistp256")
            if (keyType.contains("256")) 256
            else if (keyType.contains("384")) 384
            else if (keyType.contains("521")) 521
            else 256 // default
        }

        Some(KeyInfo(
          line = lineNum,
          keyType = keyType,
          modBits = modBits,
          exponent = "n/a",
          fpMd5 = fpMd5,
          fpSha256 = fpSha256,
          comment = comment,
          typeVer = "3"
        ))
      } catch {
        case e: Exception =>
          if (config.debug) {
            println(s"DEBUG: ECDSA parse failed - ${e.getClass.getSimpleName}: ${e.getMessage}")
          }
          None
      }
  }

  def parseEd25519Key(buffer: ByteBuffer, keyType: String, lineNum: Int, comment: String,
    fpMd5: String, fpSha256: String, config: Config): Option[KeyInfo] = {
      // ED25519 keys are always 256 bits (32 bytes)
      val modBits = 256

      Some(KeyInfo(
        line = lineNum,
        keyType = keyType,
        modBits = modBits,
        exponent = "n/a",
        fpMd5 = fpMd5,
        fpSha256 = fpSha256,
        comment = comment,
        typeVer = "4"
      ))
  }

  def parseEcdsaSkKey(buffer: ByteBuffer, keyType: String, lineNum: Int, comment: String,
    fpMd5: String, fpSha256: String, config: Config): Option[KeyInfo] = {
      try {
        // SK-ECDSA: curve name, public key point, application string
        val curveLen = buffer.getInt()
        val curveBytes = new Array[Byte](curveLen)
        buffer.get(curveBytes)
        val curveName = new String(curveBytes, "UTF-8")

        // Determine bit size from curve name
        val modBits = curveName match {
          case "nistp256" => 256
          case "nistp384" => 384
          case "nistp521" => 521
          case _ => 
            if (keyType.contains("256")) 256
            else if (keyType.contains("384")) 384
            else if (keyType.contains("521")) 521
            else 256
        }

        Some(KeyInfo(
          line = lineNum,
          keyType = keyType,
          modBits = modBits,
          exponent = "n/a",
          fpMd5 = fpMd5,
          fpSha256 = fpSha256,
          comment = comment,
          typeVer = "3"
        ))
      } catch {
        case e: Exception =>
          if (config.debug) {
            println(s"DEBUG: SK-ECDSA parse failed - ${e.getClass.getSimpleName}: ${e.getMessage}")
          }
          None
      }
  }

  def parseEd25519SkKey(buffer: ByteBuffer, keyType: String, lineNum: Int, comment: String,
    fpMd5: String, fpSha256: String, config: Config): Option[KeyInfo] = {
      // SK-ED25519 keys are always 256 bits (32 bytes), same as regular ED25519
      val modBits = 256

      Some(KeyInfo(
        line = lineNum,
        keyType = keyType,
        modBits = modBits,
        exponent = "n/a",
        fpMd5 = fpMd5,
        fpSha256 = fpSha256,
        comment = comment,
        typeVer = "4"
      ))
  }

  def computeMd5Fingerprint(bytes: Array[Byte]): String = {
    val md5 = MessageDigest.getInstance("MD5")
    val digest = md5.digest(bytes)
    digest.map(b => f"${b & 0xff}%02x").mkString(":")
  }

  def computeSha256Fingerprint(bytes: Array[Byte]): String = {
    val sha256 = MessageDigest.getInstance("SHA-256")
    val digest = sha256.digest(bytes)
    "SHA256:" + Base64.getEncoder.withoutPadding().encodeToString(digest)
  }

  def printHeader(config: Config): Unit = {
    if (config.showMd5) {
      println("Line  KeyType             Bits   Exponent    Fingerprint (MD5)                                 Comment")
      println("---- ------------------- ------ ----------- ------------------------------------------------- -------------")
    } else {
      println("Line  KeyType             Bits   Exponent    Fingerprint (SHA256)                                 Comment")
      println("---- ------------------- ------ ----------- ---------------------------------------------------- -------------")
    }
  }

  def printKeyInfo(info: KeyInfo, config: Config): Unit = {
    val isTerminal = System.console() != null

    // Determine color based on key strength
    val color = if (isTerminal && !info.failed) {
      info.keyType.toLowerCase match {
        case t if t.contains("ed25519") || t.contains("ecdsa") => "\u001b[32m" // green
        case _ if info.modBits <= 1024 => "\u001b[31m" // red
        case _ if info.modBits < 2048 => "\u001b[33m" // yellow
        case _ if info.modBits >= 4096 => "\u001b[32m" // green
        case _ => "" // 2048-3072 bits - acceptable, no color
      }
    } else ""

    val reset = if (color.nonEmpty) "\u001b[0m" else ""

    // Always show exponent
    val expDisplay = if (info.exponent.length > 10) info.exponent.take(10) else info.exponent

    if (config.showMd5 && !info.failed) {
      printf("%-4d %-20s %s%-6d%s %-11s %-49s \"%s\"\n",
        info.line, info.keyType, color, info.modBits, reset,
        expDisplay, info.fpMd5, info.comment)
    } else if (config.showMd5 && info.failed) {
      printf("%-4d %-20s %-6s %-11s %-49s \"%s\"\n",
        info.line, info.keyType,
        if (info.modBits == 0) "n/a" else info.modBits.toString,
        info.exponent, info.fpMd5, info.comment)
    } else if (!info.failed) {
      printf("%-4d %-20s %s%-6d%s %-11s %-52s \"%s\"\n",
        info.line, info.keyType, color, info.modBits, reset,
        expDisplay, info.fpSha256, info.comment)
    } else {
      printf("%-4d %-20s %-6s %-11s %-52s \"%s\"\n",
        info.line, info.keyType,
        if (info.modBits == 0) "n/a" else info.modBits.toString,
        info.exponent, info.fpSha256, info.comment)
    }
  }

  def printUsage(): Unit = {
    println(s"Usage: SSHKeyAnalyzer [-h|--help] [--md5] [-d|--debug] public_key_file")
  }

  def printInfo(): Unit = {
    println(s"\u001b[33mSSHKeyAnalyzer\u001b[0m - $VERSION  (Scala ${scala.util.Properties.versionNumberString})")
  }
}
